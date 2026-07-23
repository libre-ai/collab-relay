/**
 * @libre-ai/collab-relay — Ciphertext-only relay server.
 *
 * A WebSocket relay that forwards sealed CRDT frames between members.
 * The relay is structurally incapable of decryption:
 * - Takes NO key material as input.
 * - NEVER decrypts frame contents (ciphertext remains opaque).
 * - NEVER logs plaintext or frame structure beyond what's needed for routing.
 * - Routes frames based on epoch and member ID only.
 *
 * Each member sends sealed frames containing their document deltas.
 * The relay broadcasts these frames to all other members in the same session,
 * unchanged and encrypted. Decryption happens only at the destination (if
 * the recipient is a member of the MLS group that encrypted the frame).
 *
 * Security property: if a relay operator gains access to these frames, they
 * learn only: member ID, epoch, and frame structure (nonce length, ciphertext size).
 * They cannot read the delta contents without the MLS key.
 *
 * Frame schema (opaque to relay):
 *   { id: string, epoch: number, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array }
 *
 * Message types on WebSocket:
 *   { type: "join", sessionId: string, memberId: string }
 *   { type: "sealed-frame", sessionId: string, frame: {...} }
 *   { type: "leave", sessionId: string, memberId: string }
 */

/**
 * A sealed frame as received from or sent to a relay client.
 *
 * The relay never looks inside ciphertext or validates the frame format;
 * it only routes based on sessionId, epoch, and memberId.
 */
export interface RelayFrame {
  /** Unique member ID (sender identification). */
  readonly id: string;
  /** Epoch of the frame (for filtering, not decryption). */
  readonly epoch: number;
  /** Initialization vector (opaque to relay). */
  readonly nonce: Uint8Array;
  /** Encrypted delta (opaque to relay). */
  readonly ciphertext: Uint8Array;
  /** Authentication tag (opaque to relay). */
  readonly tag: Uint8Array;
}

/**
 * A message sent over the relay's WebSocket connection.
 */
export interface RelayMessage {
  type: "join" | "sealed-frame" | "leave";
  sessionId: string;
  memberId?: string;
  frame?: RelayFrame;
}

/**
 * A WebSocket connection for the relay. Due to Bun's ServerWebSocket type
 * constraints, we use a minimalist interface focusing on the methods we need.
 */
interface RelayWebSocket {
  send(data: string | Uint8Array | Buffer): void;
  close(code?: number, reason?: string): void;
  readyState: number;
}

/**
 * In-memory session state: tracks members and routes frames.
 */
interface SessionState {
  members: Map<string, RelayWebSocket>;
}

/**
 * CiphertextOnlyRelayServer — forwards sealed frames opaquely.
 *
 * The relay maintains session state (member list) and broadcasts incoming
 * frames to all other members in the session. It performs NO decryption,
 * NO key management, and NO plaintext logging.
 *
 * Usage:
 *   const relay = new CiphertextOnlyRelayServer();
 *   relay.serve({ hostname: "0.0.0.0", port: 9000 });
 */
export class CiphertextOnlyRelayServer {
  private sessions: Map<string, SessionState> = new Map();

  /**
   * Start the relay server on the given host and port.
   *
   * @param config - Server configuration (hostname, port).
   */
  async serve(config: { hostname: string; port: number }): Promise<void> {
    const _server = Bun.serve({
      hostname: config.hostname,
      port: config.port,

      // biome-ignore lint/suspicious/noExplicitAny: Bun's server type not exported
      fetch: (request: Request, server: any) => {
        // Check if this is a WebSocket upgrade request
        if (request.headers.get("upgrade") === "websocket") {
          const success = server.upgrade(request, {
            data: {}, // No per-connection context needed yet
          });
          if (!success) {
            return new Response("Upgrade failed", { status: 400 });
          }
          return undefined;
        }

        // Non-WebSocket requests get a 404
        return new Response("Not Found", { status: 404 });
      },

      websocket: {
        open: (_ws: RelayWebSocket) => {
          // Member connected; wait for join message
          // No per-connection state stored yet
        },

        message: (ws: RelayWebSocket, message: string | Buffer) => {
          // Parse the incoming message
          let msg: RelayMessage;
          try {
            let raw: string;
            if (typeof message === "string") {
              raw = message;
            } else {
              // Buffer from Bun server can be decoded directly
              // biome-ignore lint/suspicious/noExplicitAny: Bun's Buffer type not fully exported
              const buffer = Buffer.isBuffer(message) ? message : new Uint8Array(message as any);
              raw = new TextDecoder().decode(buffer);
            }
            msg = JSON.parse(raw);
          } catch {
            // Malformed JSON; close connection
            ws.close(1008, "Invalid message format");
            return;
          }

          // Route by message type
          if (msg.type === "join") {
            this.handleJoin(ws, msg);
          } else if (msg.type === "sealed-frame") {
            this.handleSealedFrame(ws, msg);
          } else if (msg.type === "leave") {
            this.handleLeave(msg);
          }
        },

        close: (ws: RelayWebSocket) => {
          // Member disconnected; find and remove from all sessions
          this.removeClientFromAllSessions(ws);
        },
      },
    });

    console.log(`Ciphertext-only relay listening on ${config.hostname}:${config.port}`);
    console.log("(relay does not decrypt or log plaintext)");
  }

  /**
   * Handle a join message: register the member in the session.
   *
   * ⚠ The relay does NOT validate that the member is actually a member of the
   * MLS group (that validation happens at the destination, when the frame is
   * decrypted). This design keeps the relay stateless and key-agnostic.
   *
   * @param ws - The WebSocket connection.
   * @param msg - The join message.
   */
  private handleJoin(ws: RelayWebSocket, msg: RelayMessage): void {
    const sessionId = msg.sessionId;
    const memberId = msg.memberId;

    if (!sessionId || !memberId) {
      ws.close(1008, "Missing sessionId or memberId");
      return;
    }

    // Ensure session exists
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, { members: new Map() });
    }

    const session = this.sessions.get(sessionId);
    if (!session) {
      ws.close(1011, "Session not found");
      return;
    }
    session.members.set(memberId, ws);

    // Send acknowledgment
    ws.send(
      JSON.stringify({
        type: "joined",
        sessionId,
        memberId,
      }),
    );
  }

  /**
   * Handle a sealed-frame message: broadcast to all other members in the session.
   *
   * The relay does not inspect or validate the frame contents. It only checks
   * that the frame has the required structure (id, epoch, nonce, ciphertext, tag).
   *
   * ⚠ NEVER DECRYPT the ciphertext field.
   * ⚠ NEVER LOG the plaintext or plaintext size.
   *
   * @param sender - The WebSocket that sent this frame (will not receive it back).
   * @param msg - The message containing the sealed frame.
   */
  private handleSealedFrame(sender: RelayWebSocket, msg: RelayMessage): void {
    const sessionId = msg.sessionId;
    const frame = msg.frame;

    if (!sessionId || !frame) {
      sender.close(1008, "Missing sessionId or frame");
      return;
    }

    // Validate frame structure (routing fields only)
    if (!frame.id || typeof frame.epoch !== "number") {
      sender.close(1008, "Invalid frame structure");
      return;
    }

    // Do NOT validate frame.nonce, ciphertext, or tag lengths; keep the relay stateless.

    // Broadcast to all other members in the session
    const session = this.sessions.get(sessionId);
    if (!session) {
      // Session doesn't exist; silently ignore (client may be out of sync)
      return;
    }

    const messageStr = JSON.stringify({
      type: "sealed-frame",
      sessionId,
      frame: {
        id: frame.id,
        epoch: frame.epoch,
        nonce: Array.from(frame.nonce),
        ciphertext: Array.from(frame.ciphertext),
        tag: Array.from(frame.tag),
      },
    });

    for (const [_memberId, client] of session.members) {
      // Do not send back to sender
      if (client === sender) {
        continue;
      }

      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(messageStr);
        } catch {
          // Client may have disconnected; ignore
        }
      }
    }
  }

  /**
   * Handle a leave message: remove member from the session.
   *
   * @param msg - The leave message.
   */
  private handleLeave(msg: RelayMessage): void {
    const sessionId = msg.sessionId;
    const memberId = msg.memberId;

    if (!sessionId || !memberId) {
      return;
    }

    const session = this.sessions.get(sessionId);
    if (session) {
      session.members.delete(memberId);
      if (session.members.size === 0) {
        this.sessions.delete(sessionId);
      }
    }
  }

  /**
   * Remove a WebSocket connection from all sessions.
   *
   * Called when a client disconnects.
   *
   * @param ws - The WebSocket connection to remove.
   */
  private removeClientFromAllSessions(ws: RelayWebSocket): void {
    for (const session of this.sessions.values()) {
      for (const [memberId, client] of session.members) {
        if (client === ws) {
          session.members.delete(memberId);
          break;
        }
      }
    }

    // Clean up empty sessions
    for (const [sessionId, session] of this.sessions) {
      if (session.members.size === 0) {
        this.sessions.delete(sessionId);
      }
    }
  }
}
