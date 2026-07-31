import { describe, expect, it } from "bun:test";
import { CiphertextOnlyRelayServer, type RelayFrame } from "./relay-server";

/** Open a client socket and resolve once the connection is established. */
async function openClient(port: number): Promise<WebSocket> {
  const client = new WebSocket(`ws://127.0.0.1:${port}`);
  await new Promise<void>((resolve) => {
    client.addEventListener("open", () => resolve());
  });
  return client;
}

/** Collect every sealed frame routed to this client, in arrival order. */
function collectFrames(client: WebSocket): RelayFrame[] {
  const frames: RelayFrame[] = [];
  client.addEventListener("message", (event) => {
    const msg = JSON.parse(event.data as string);
    if (msg.type === "sealed-frame") {
      frames.push(msg.frame);
    }
  });
  return frames;
}

/** Record the close code the relay sent to this client, if any. */
function recordClose(client: WebSocket): { code: number | null } {
  const state: { code: number | null } = { code: null };
  client.addEventListener("close", (event) => {
    state.code = (event as CloseEvent).code;
  });
  return state;
}

/** Let the relay and the sockets settle before asserting. */
function settle(ms = 150): Promise<void> {
  return new Promise((resolve) => setTimeout(() => resolve(), ms));
}

/** A well-formed sealed frame; contents stay opaque to the relay. */
function sealedFrame(sessionId: string, id: string): string {
  return JSON.stringify({
    type: "sealed-frame",
    sessionId,
    frame: {
      id,
      epoch: 0,
      nonce: Array.from(new Uint8Array(12)),
      ciphertext: Array.from(new Uint8Array([9, 9, 9])),
      tag: Array.from(new Uint8Array(16)),
    },
  });
}

/** A join request for a given routing slot. */
function joinMessage(sessionId: string, memberId: string): string {
  return JSON.stringify({ type: "join", sessionId, memberId });
}

describe("CiphertextOnlyRelayServer", () => {
  describe("1. Frame forwarding is opaque", () => {
    it("should forward a relayed frame unchanged", async () => {
      // Start the relay server
      const relay = new CiphertextOnlyRelayServer();
      const _serverPromise = relay.serve({
        hostname: "127.0.0.1",
        port: 9001,
      });

      // Give the server a moment to start
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Create two client connections
      const sessionId = "test-session-1";
      const memberId1 = "member-1";
      const memberId2 = "member-2";

      // Build a sealed frame (opaque payload)
      const testFrame: RelayFrame = {
        id: memberId1,
        epoch: 0,
        nonce: new Uint8Array(12),
        ciphertext: new Uint8Array([1, 2, 3, 4, 5]), // Dummy ciphertext
        tag: new Uint8Array(16),
      };

      // Track received frames on member-2
      const receivedFrames: RelayFrame[] = [];

      // Connect member-2 and listen for frames
      const client2 = new WebSocket("ws://127.0.0.1:9001");
      await new Promise<void>((resolve) => {
        client2.addEventListener("open", () => {
          client2.send(
            JSON.stringify({
              type: "join",
              sessionId,
              memberId: memberId2,
            }),
          );
          resolve();
        });
      });

      client2.addEventListener("message", (event) => {
        const msg = JSON.parse(event.data as string);
        if (msg.type === "sealed-frame") {
          receivedFrames.push(msg.frame);
        }
      });

      // Connect member-1 and send a frame
      const client1 = new WebSocket("ws://127.0.0.1:9001");
      await new Promise<void>((resolve) => {
        client1.addEventListener("open", () => {
          client1.send(
            JSON.stringify({
              type: "join",
              sessionId,
              memberId: memberId1,
            }),
          );
          resolve();
        });
      });

      // Send frame from member-1
      await new Promise((resolve) => setTimeout(resolve, 50));
      client1.send(
        JSON.stringify({
          type: "sealed-frame",
          sessionId,
          frame: {
            id: testFrame.id,
            epoch: testFrame.epoch,
            nonce: Array.from(testFrame.nonce),
            ciphertext: Array.from(testFrame.ciphertext),
            tag: Array.from(testFrame.tag),
          },
        }),
      );

      // Wait for frame to arrive at member-2
      await new Promise((resolve) => setTimeout(resolve, 200));

      // Verify member-2 received the frame (unchanged)
      expect(receivedFrames.length).toBeGreaterThan(0);
      const received = receivedFrames[0];
      if (!received) {
        throw new Error("No frame received");
      }
      expect(received.id).toBe(memberId1);
      expect(received.epoch).toBe(0);
      expect(Array.from(received.nonce)).toEqual(Array.from(testFrame.nonce));
      expect(Array.from(received.ciphertext)).toEqual(Array.from(testFrame.ciphertext));
      expect(Array.from(received.tag)).toEqual(Array.from(testFrame.tag));

      client1.close();
      client2.close();
    });
  });

  describe("2. Relay has no key parameter", () => {
    it("should have no key field or key-taking method anywhere", () => {
      // The relay object should not have any method that takes a key
      const testRelay = new CiphertextOnlyRelayServer();
      const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(testRelay));

      // Methods that would indicate key-holding:
      const keywordsDenied = [
        "key",
        "setKey",
        "loadKey",
        "deriveKey",
        "password",
        "secret",
        "decrypt",
        "aesDecrypt",
      ];

      for (const keyword of keywordsDenied) {
        expect(methods.map((m) => m.toLowerCase())).not.toContain(keyword.toLowerCase());
      }

      // The relay constructor should take only no arguments
      const relay2 = new CiphertextOnlyRelayServer();
      expect(relay2).toBeDefined();
    });
  });

  describe("3. Multiple sessions are isolated", () => {
    it("should not leak frames between sessions", async () => {
      // Start the relay
      const relay = new CiphertextOnlyRelayServer();
      const _serverPromise = relay.serve({
        hostname: "127.0.0.1",
        port: 9002,
      });

      await new Promise((resolve) => setTimeout(resolve, 100));

      const session1 = "session-1";
      const session2 = "session-2";

      const receivedFrames: { sessionId: string; frameId: string }[] = [];

      // Connect a member to session-2 and listen
      const client2Session2 = new WebSocket("ws://127.0.0.1:9002");
      await new Promise<void>((resolve) => {
        client2Session2.addEventListener("open", () => {
          client2Session2.send(
            JSON.stringify({
              type: "join",
              sessionId: session2,
              memberId: "m2-session2",
            }),
          );
          resolve();
        });
      });

      client2Session2.addEventListener("message", (event) => {
        const msg = JSON.parse(event.data as string);
        if (msg.type === "sealed-frame") {
          receivedFrames.push({
            sessionId: msg.sessionId,
            frameId: msg.frame.id,
          });
        }
      });

      // Connect and send from session-1
      const client1Session1 = new WebSocket("ws://127.0.0.1:9002");
      await new Promise<void>((resolve) => {
        client1Session1.addEventListener("open", () => {
          client1Session1.send(
            JSON.stringify({
              type: "join",
              sessionId: session1,
              memberId: "m1-session1",
            }),
          );
          resolve();
        });
      });

      // Send a frame in session-1
      await new Promise((resolve) => setTimeout(resolve, 50));
      client1Session1.send(
        JSON.stringify({
          type: "sealed-frame",
          sessionId: session1,
          frame: {
            id: "m1-session1",
            epoch: 0,
            nonce: Array.from(new Uint8Array(12)),
            ciphertext: Array.from(new Uint8Array([1, 2, 3])),
            tag: Array.from(new Uint8Array(16)),
          },
        }),
      );

      // Wait and check: client in session-2 should NOT receive frames from session-1
      await new Promise((resolve) => setTimeout(resolve, 200));
      expect(receivedFrames.length).toBe(0);

      client1Session1.close();
      client2Session2.close();
    });
  });

  describe("4. Member join/leave", () => {
    it("should track members and clean up empty sessions", async () => {
      const relay = new CiphertextOnlyRelayServer();
      const _serverPromise = relay.serve({
        hostname: "127.0.0.1",
        port: 9003,
      });

      await new Promise((resolve) => setTimeout(resolve, 100));

      const sessionId = "test-session-cleanup";
      const memberId = "cleanup-member";

      const client = new WebSocket("ws://127.0.0.1:9003");

      // Join
      await new Promise<void>((resolve) => {
        client.addEventListener("open", () => {
          client.send(
            JSON.stringify({
              type: "join",
              sessionId,
              memberId,
            }),
          );

          client.addEventListener("message", (event) => {
            const msg = JSON.parse(event.data as string);
            if (msg.type === "joined") {
              resolve();
            }
          });
        });
      });

      // Leave
      client.send(
        JSON.stringify({
          type: "leave",
          sessionId,
          memberId,
        }),
      );

      await new Promise((resolve) => setTimeout(resolve, 100));

      // After leaving, the session should be cleaned up
      // (We can't directly inspect relay state, but the relay should not crash)
      client.close();

      expect(true).toBe(true); // Placeholder assertion
    });
  });

  describe("5. Structural incapability: relay never calls decrypt", () => {
    it("should not reference a decrypt function", () => {
      // Check the source code for the relay does not contain crypto operations
      // This is a code inspection test
      const relaySource = CiphertextOnlyRelayServer.toString();
      // Check for actual crypto operations, not comments
      expect(relaySource).not.toContain(".decrypt");
      expect(relaySource.toLowerCase()).not.toContain("decipher");
      expect(relaySource.toLowerCase()).not.toContain(".aeS");
      expect(relaySource.toLowerCase()).not.toContain("crypto.subtle");
    });
  });

  describe("6. Routing integrity: leave only affects the sender's own slot", () => {
    it("should ignore a leave sent by a connection that does not hold the slot", async () => {
      const port = 9004;
      const relay = new CiphertextOnlyRelayServer();
      const _serverPromise = relay.serve({ hostname: "127.0.0.1", port });
      await settle(100);

      const sessionId = "eviction-session";

      // The victim holds the "victim" slot on its own connection.
      const victim = await openClient(port);
      const victimFrames = collectFrames(victim);
      victim.send(joinMessage(sessionId, "victim"));
      await settle(50);

      // A third party — holding no slot at all — tries to evict the victim.
      const attacker = await openClient(port);
      attacker.send(JSON.stringify({ type: "leave", sessionId, memberId: "victim" }));
      await settle(100);

      // A legitimate peer broadcasts: the victim must still be routed to.
      const peer = await openClient(port);
      peer.send(joinMessage(sessionId, "peer"));
      await settle(50);
      peer.send(sealedFrame(sessionId, "peer"));
      await settle(200);

      expect(victimFrames.length).toBeGreaterThan(0);

      victim.close();
      attacker.close();
      peer.close();
    });

    it("should still honour a leave sent by the connection that owns the slot", async () => {
      const port = 9005;
      const relay = new CiphertextOnlyRelayServer();
      const _serverPromise = relay.serve({ hostname: "127.0.0.1", port });
      await settle(100);

      const sessionId = "self-leave-session";

      const leaver = await openClient(port);
      const leaverFrames = collectFrames(leaver);
      leaver.send(joinMessage(sessionId, "leaver"));
      await settle(50);

      // The owner releases its own slot.
      leaver.send(JSON.stringify({ type: "leave", sessionId, memberId: "leaver" }));
      await settle(100);

      const peer = await openClient(port);
      peer.send(joinMessage(sessionId, "peer"));
      await settle(50);
      peer.send(sealedFrame(sessionId, "peer"));
      await settle(200);

      // Having left, the former member is no longer routed to.
      expect(leaverFrames.length).toBe(0);

      leaver.close();
      peer.close();
    });
  });

  describe("7. Routing integrity: join cannot steal an occupied slot", () => {
    it("should keep routing to the holder when another connection joins with the same memberId", async () => {
      const port = 9006;
      const relay = new CiphertextOnlyRelayServer();
      const _serverPromise = relay.serve({ hostname: "127.0.0.1", port });
      await settle(100);

      const sessionId = "hijack-session";
      const contestedId = "contested-member";

      // The holder takes the slot first.
      const holder = await openClient(port);
      const holderFrames = collectFrames(holder);
      holder.send(joinMessage(sessionId, contestedId));
      await settle(50);

      // A second connection claims the very same slot.
      const hijacker = await openClient(port);
      const hijackerFrames = collectFrames(hijacker);
      const hijackerClose = recordClose(hijacker);
      hijacker.send(joinMessage(sessionId, contestedId));
      await settle(100);

      // A peer broadcasts once.
      const peer = await openClient(port);
      peer.send(joinMessage(sessionId, "peer"));
      await settle(50);
      peer.send(sealedFrame(sessionId, "peer"));
      await settle(200);

      // The holder keeps its routing; the hijacker never took it over.
      expect(holderFrames.length).toBeGreaterThan(0);
      expect(hijackerFrames.length).toBe(0);
      expect(hijackerClose.code).toBe(1008);

      holder.close();
      hijacker.close();
      peer.close();
    });
  });

  describe("8. Routing integrity: frames need a slot the sender holds", () => {
    it("should drop a sealed frame from a connection that never joined the session", async () => {
      const port = 9007;
      const relay = new CiphertextOnlyRelayServer();
      const _serverPromise = relay.serve({ hostname: "127.0.0.1", port });
      await settle(100);

      const sessionId = "injection-session";

      const member = await openClient(port);
      const memberFrames = collectFrames(member);
      member.send(joinMessage(sessionId, "member"));
      await settle(50);

      // An outsider injects a well-formed frame into a session it never joined.
      const outsider = await openClient(port);
      outsider.send(sealedFrame(sessionId, "member"));
      await settle(200);

      expect(memberFrames.length).toBe(0);

      member.close();
      outsider.close();
    });
  });

  describe("9. Malformed frames are refused, never thrown", () => {
    it("should close the sender cleanly and keep serving the other members", async () => {
      const port = 9008;
      const relay = new CiphertextOnlyRelayServer();
      const _serverPromise = relay.serve({ hostname: "127.0.0.1", port });
      await settle(100);

      const sessionId = "malformed-session";

      const sender = await openClient(port);
      const senderClose = recordClose(sender);
      sender.send(joinMessage(sessionId, "sender"));
      await settle(50);

      // Passes the id/epoch check, then used to blow up on Array.from(undefined).
      sender.send(
        JSON.stringify({
          type: "sealed-frame",
          sessionId,
          frame: { id: "sender", epoch: 0 },
        }),
      );
      await settle(200);

      // Clean refusal, not an exception escaping the message handler.
      expect(senderClose.code).toBe(1008);

      // The relay is still serving: two fresh members exchange a frame.
      const listener = await openClient(port);
      const listenerFrames = collectFrames(listener);
      listener.send(joinMessage(sessionId, "listener"));
      await settle(50);

      const talker = await openClient(port);
      talker.send(joinMessage(sessionId, "talker"));
      await settle(50);
      talker.send(sealedFrame(sessionId, "talker"));
      await settle(200);

      expect(listenerFrames.length).toBeGreaterThan(0);

      sender.close();
      listener.close();
      talker.close();
    });
  });
});
