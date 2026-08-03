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
 * Threat model
 * ------------
 * Confidentiality is out of the relay's hands by construction: it holds no key
 * and never decrypts. An operator with access to the frames learns only member
 * ID, epoch, and frame structure (nonce length, ciphertext size); the delta
 * contents stay unreadable without the MLS key.
 *
 * Availability and routing integrity ARE the relay's responsibility, because it
 * owns the session-to-connection map that decides who receives what. Every
 * mutation of that map is therefore bound to the connection requesting it: a
 * client may take a free slot, and may only release or send on a slot it holds
 * on its own socket. Without that binding any connected client could evict any
 * member of any session (targeted denial of service) or take over a member's
 * slot at join time and silently black-hole its traffic. Neither attack needs a
 * key, so the ciphertext-only design does not defend against them on its own.
 *
 * Binding those mutations also closes the path by which a third party used to
 * purge a slot the relay had failed to release, so the relay owns the release
 * itself: a disconnecting socket gives up EVERY slot it held, in every session,
 * and a session emptied that way is collected. Releasing only the first would
 * strand a routing entry on a closed socket and retain its session forever —
 * memory growth driven remotely, without a key, at one WebSocket and two frames
 * per session.
 *
 * Releasing what is finished is only half of it: a session is created by
 * whoever asks for one, so admission is capped as well. The routing map holds
 * at most `maxSessions` sessions of at most `maxMembersPerSession` slots, and a
 * join over either ceiling is refused with close code 1013 rather than served.
 * Without that cap the map grows as fast as a client can send frames, and no
 * amount of correct release helps.
 *
 * Not defended, deliberately:
 * - MLS group membership is NOT validated here. A client may hold a slot in a
 *   session whose frames it cannot decrypt; that check belongs at the
 *   destination, where the AEAD tag is verified.
 * - The `id` field inside a frame is not authenticated. It is routing metadata,
 *   not a claim of identity — recipients trust the AEAD tag, not this field.
 * - A *free* slot is first-come-first-served: the relay has no identity
 *   provider, so it cannot tell a legitimate member from a squatter claiming
 *   the memberId first. The guarantee stops at "a slot that is taken cannot be
 *   stolen, released, or sent on by a third party"; pre-emptive squatting
 *   remains possible and now surfaces as an explicit join refusal (1008)
 *   instead of a silent takeover.
 * - Admission is bounded, not fair. The ceilings cap what the routing map can
 *   hold in total; they do not stop one client from filling it and starving
 *   everybody else, because a client refused on one socket simply opens
 *   another and the relay has no identity to charge the quota to. Per-client
 *   fairness needs a rate limiter or an authenticated front end above this
 *   layer; the ceiling here only guarantees that the memory stops growing.
 * - Frame rate and frame size are not limited. A member holding a slot can
 *   spend the relay's bandwidth and its peers' attention freely; the routing
 *   map, which is what this file owns, stays bounded either way.
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
 * Ceilings on what the relay will admit.
 *
 * A session is created on demand by whoever asks for it, so without a ceiling
 * the routing map grows as fast as an unauthenticated client can send frames.
 * These two numbers are the only thing that bounds the relay's memory.
 */
export interface RelayLimits {
  /** Maximum number of sessions held at once. */
  readonly maxSessions: number;
  /** Maximum number of routing slots inside one session. */
  readonly maxMembersPerSession: number;
}

/**
 * Default ceilings: at most 1024 sessions of at most 128 members, so the
 * routing map cannot exceed 131 072 slots whatever any client does.
 */
const DEFAULT_LIMITS: RelayLimits = {
  maxSessions: 1024,
  maxMembersPerSession: 128,
};

/**
 * A census of what the routing map currently holds.
 *
 * Occupancy is the relay's own availability surface: it is the thing that
 * grows when a session is retained after everyone left, and the thing an
 * operator has to watch on a brick that claims availability as its
 * responsibility. Counting it is the only way to tell a live session from a
 * retained one from the outside.
 */
export interface RelayStats {
  /** Sessions currently held in memory. */
  readonly sessions: number;
  /** Routing slots across all sessions. */
  readonly slots: number;
  /** Slots whose socket is no longer OPEN — each one is a retained corpse. */
  readonly staleSlots: number;
}

/**
 * A running relay: the port it actually bound, and the means to stop it.
 *
 * `serve` used to discard the server object, so a started relay could never be
 * stopped: its listener outlived the caller (a test file leaked one listener
 * per test) and the port had to be known in advance. The handle closes both
 * gaps — `port` resolves an ephemeral `port: 0` to the port really bound.
 */
export interface RelayHandle {
  /** The port actually bound; resolved, so `port: 0` is usable. */
  readonly port: number;
  /**
   * Stop listening and force-close the connections still open.
   *
   * Synchronous on purpose. Bun 1.4.0-canary.1 returns a promise from
   * `Server.stop()` that never settles once the server has itself closed a
   * socket — one `ws.close(1008, …)` refusal is enough — while the listening
   * socket is released either way: the port re-binds on the next statement.
   * Awaiting the drain would hang the caller; releasing the listener is the
   * guarantee this handle can actually keep.
   */
  stop(): void;
}

/**
 * Shape check for an opaque frame field: present and array-like.
 *
 * The relay re-serialises nonce/ciphertext/tag verbatim and never inspects
 * their length or content. It does have to know they exist: re-serialising an
 * absent field throws out of the WebSocket message handler, turning any
 * malformed frame into an unhandled exception and a remotely triggered stack
 * trace on the relay's stderr.
 */
function isByteSequence(value: unknown): boolean {
  return Array.isArray(value) || ArrayBuffer.isView(value);
}

/** A capacity ceiling only means something as a positive whole number. */
function isPositiveInteger(value: number): boolean {
  return Number.isInteger(value) && value > 0;
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
 *   const handle = await relay.serve({ hostname: "0.0.0.0", port: 9000 });
 *
 * Capacity ceilings are the only constructor argument, and never key material:
 *   new CiphertextOnlyRelayServer({ maxSessions: 64, maxMembersPerSession: 8 });
 */
export class CiphertextOnlyRelayServer {
  private sessions: Map<string, SessionState> = new Map();

  private readonly limits: RelayLimits;

  /**
   * @param limits - Capacity ceilings; each one defaults to {@link DEFAULT_LIMITS}.
   * @throws RangeError - If a ceiling is not a positive whole number. A zero or
   *         negative ceiling would silently close the relay for business, which
   *         is worse than refusing to start.
   */
  constructor(limits: Partial<RelayLimits> = {}) {
    const resolved: RelayLimits = {
      maxSessions: limits.maxSessions ?? DEFAULT_LIMITS.maxSessions,
      maxMembersPerSession: limits.maxMembersPerSession ?? DEFAULT_LIMITS.maxMembersPerSession,
    };

    if (!isPositiveInteger(resolved.maxSessions)) {
      throw new RangeError(`maxSessions must be a positive integer, got ${resolved.maxSessions}`);
    }
    if (!isPositiveInteger(resolved.maxMembersPerSession)) {
      throw new RangeError(
        `maxMembersPerSession must be a positive integer, got ${resolved.maxMembersPerSession}`,
      );
    }

    this.limits = resolved;
  }

  /**
   * Start the relay server on the given host and port.
   *
   * @param config - Server configuration (hostname, port; port 0 binds a free one).
   * @returns A handle carrying the bound port and a stop function.
   */
  async serve(config: { hostname: string; port: number }): Promise<RelayHandle> {
    const server = Bun.serve({
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
            this.handleLeave(ws, msg);
          }
        },

        close: (ws: RelayWebSocket) => {
          // Member disconnected; find and remove from all sessions
          this.removeClientFromAllSessions(ws);
        },
      },
    });

    const port = server.port ?? config.port;
    console.log(`Ciphertext-only relay listening on ${config.hostname}:${port}`);
    console.log("(relay does not decrypt or log plaintext)");

    return {
      port,
      stop: (): void => {
        // Fire and forget: see RelayHandle.stop on why the promise is dropped.
        void server.stop(true);
      },
    };
  }

  /**
   * Count what the routing map holds right now.
   *
   * Read-only: mutates nothing, inspects no frame content, allocates one small
   * object per call. Occupancy is derived on demand rather than kept as a
   * counter, so it cannot drift away from the map it describes.
   *
   * @returns The number of sessions, of routing slots, and of slots whose
   *          socket is no longer OPEN.
   */
  stats(): RelayStats {
    let slots = 0;
    let staleSlots = 0;

    for (const session of this.sessions.values()) {
      for (const client of session.members.values()) {
        slots++;
        if (client.readyState !== WebSocket.OPEN) {
          staleSlots++;
        }
      }
    }

    return { sessions: this.sessions.size, slots, staleSlots };
  }

  /**
   * Handle a join message: register the member in the session.
   *
   * ⚠ The relay does NOT validate that the member is actually a member of the
   * MLS group (that validation happens at the destination, when the frame is
   * decrypted). This design keeps the relay stateless and key-agnostic.
   *
   * It does own the routing slot, however: an occupied slot is never
   * overwritten, because overwriting it would silently redirect the holder's
   * traffic to the newcomer. And it owns the allocation: a join is the only
   * thing that grows the routing map, so both capacity ceilings are enforced
   * here, refused with close code 1013 (try again later).
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

    // Create the session on demand, but only while there is room for one. The
    // ceiling is checked before the allocation, not after: creating first and
    // refusing after would let a client the relay just refused allocate an
    // empty session per frame anyway.
    let session = this.sessions.get(sessionId);
    if (!session) {
      if (this.sessions.size >= this.limits.maxSessions) {
        ws.close(1013, "Relay at session capacity");
        return;
      }

      session = { members: new Map() };
      this.sessions.set(sessionId, session);
    }

    // A routing slot belongs to the connection that took it. Refuse a claim on
    // an occupied one instead of overwriting it, which would black-hole the
    // holder's traffic without either party noticing. A slot whose socket is no
    // longer OPEN is stale (its close handler has not run yet) and may be
    // reclaimed; re-joining from the same socket stays idempotent.
    const holder = session.members.get(memberId);
    if (holder && holder !== ws && holder.readyState === WebSocket.OPEN) {
      ws.close(1008, "memberId already in use in this session");
      return;
    }

    // Only a slot the session does not have yet consumes capacity. Charging a
    // re-join would lock a member out of the session it is already in as soon
    // as that session filled up — a retry or a reconnect must not be refused.
    if (!holder && session.members.size >= this.limits.maxMembersPerSession) {
      ws.close(1013, "Session at member capacity");
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

    // Do NOT validate frame.nonce, ciphertext, or tag lengths; keep the relay
    // stateless. Their presence is another matter: they are re-serialised
    // below, and an absent one throws out of the message handler.
    if (
      !isByteSequence(frame.nonce) ||
      !isByteSequence(frame.ciphertext) ||
      !isByteSequence(frame.tag)
    ) {
      sender.close(1008, "Invalid frame structure");
      return;
    }

    // Broadcast to all other members in the session
    const session = this.sessions.get(sessionId);
    if (!session) {
      // Session doesn't exist; silently ignore (client may be out of sync)
      return;
    }

    // Only a connection holding a slot in this session gets its frames fanned
    // out; otherwise any client could inject into any session it never joined.
    // Dropped silently: a frame in flight just after a leave is a race, not an
    // attack, and closing on it would punish a legitimate client.
    if (!this.holdsSlot(session, sender)) {
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
   * Handle a leave message: release the sender's own slot in the session.
   *
   * The removal is bound to the requesting connection: the relay drops a leave
   * naming a slot this socket does not hold. Without that check any connected
   * client could evict any memberId from any sessionId — an unauthenticated,
   * remote, targeted denial of service.
   *
   * @param ws - The WebSocket connection that sent this message.
   * @param msg - The leave message.
   */
  private handleLeave(ws: RelayWebSocket, msg: RelayMessage): void {
    const sessionId = msg.sessionId;
    const memberId = msg.memberId;

    if (!sessionId || !memberId) {
      return;
    }

    const session = this.sessions.get(sessionId);
    if (!session) {
      return;
    }

    // Only the holder of the slot may release it.
    if (session.members.get(memberId) !== ws) {
      return;
    }

    session.members.delete(memberId);
    if (session.members.size === 0) {
      this.sessions.delete(sessionId);
    }
  }

  /**
   * Whether this connection currently holds a routing slot in the session.
   *
   * @param session - The session to look in.
   * @param ws - The WebSocket connection to look for.
   */
  private holdsSlot(session: SessionState, ws: RelayWebSocket): boolean {
    for (const client of session.members.values()) {
      if (client === ws) {
        return true;
      }
    }
    return false;
  }

  /**
   * Release every routing slot held by a connection, in every session.
   *
   * Called when a client disconnects.
   *
   * The sweep is exhaustive on purpose: nothing stops one socket from holding
   * several slots in the same session, and stopping at the first match leaves
   * the others pointing at a closed socket. Such a session never reaches zero
   * members, so it is never collected — unbounded memory growth that any
   * unauthenticated client drives at one WebSocket and two frames per session.
   * Since a leave is now bound to the slot's holder, a stranded slot has no
   * remaining purge path either.
   *
   * @param ws - The WebSocket connection to remove.
   */
  private removeClientFromAllSessions(ws: RelayWebSocket): void {
    for (const [sessionId, session] of this.sessions) {
      for (const [memberId, client] of session.members) {
        if (client === ws) {
          session.members.delete(memberId);
        }
      }

      if (session.members.size === 0) {
        this.sessions.delete(sessionId);
      }
    }
  }
}
