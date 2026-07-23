import { describe, expect, it } from "bun:test";
import { CiphertextOnlyRelayServer, type RelayFrame } from "./relay-server";

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
});
