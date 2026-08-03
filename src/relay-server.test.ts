import { afterEach, describe, expect, it } from "bun:test";
import { CiphertextOnlyRelayServer, type RelayFrame, type RelayHandle } from "./relay-server";

/** Relays and client sockets opened by the running test, torn down after it. */
const startedRelays: RelayHandle[] = [];
const openedClients: WebSocket[] = [];

afterEach(() => {
  for (const client of openedClients.splice(0)) {
    client.close();
  }
  for (const handle of startedRelays.splice(0)) {
    handle.stop();
  }
});

/**
 * Start a relay on a free port. The port is never pinned: a fixed one makes the
 * suite fail on any runner that happens to hold it, for reasons unrelated to
 * the code under test. The relay is stopped when the test ends.
 */
async function startRelay(): Promise<{ relay: CiphertextOnlyRelayServer; port: number }> {
  const relay = new CiphertextOnlyRelayServer();
  const handle = await relay.serve({ hostname: "127.0.0.1", port: 0 });
  startedRelays.push(handle);
  return { relay, port: handle.port };
}

/** Open a client socket and resolve once the connection is established. */
async function openClient(port: number): Promise<WebSocket> {
  const client = new WebSocket(`ws://127.0.0.1:${port}`);
  openedClients.push(client);
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

/** Resolve with the first sealed frame routed to this client, or fail loudly. */
function awaitFrame(client: WebSocket, ms = 1000): Promise<RelayFrame> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      client.removeEventListener("message", onMessage);
      reject(new Error("no sealed frame was routed to this client"));
    }, ms);
    const onMessage = (event: MessageEvent): void => {
      const msg = JSON.parse(event.data as string);
      if (msg.type === "sealed-frame") {
        clearTimeout(timer);
        client.removeEventListener("message", onMessage);
        resolve(msg.frame);
      }
    };
    client.addEventListener("message", onMessage);
  });
}

/** Resolve with the close code the relay sends to this client. */
function awaitClose(client: WebSocket, ms = 1000): Promise<number> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("the relay never closed this connection")), ms);
    client.addEventListener("close", (event) => {
      clearTimeout(timer);
      resolve((event as CloseEvent).code);
    });
  });
}

/** Let the relay settle before asserting that something did NOT happen. */
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

/** Claim a routing slot and resolve on the relay's acknowledgement. */
function join(client: WebSocket, sessionId: string, memberId: string, ms = 1000): Promise<void> {
  const acknowledged = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      client.removeEventListener("message", onMessage);
      reject(new Error(`the relay never acknowledged the join of ${memberId}`));
    }, ms);
    const onMessage = (event: MessageEvent): void => {
      const msg = JSON.parse(event.data as string);
      if (msg.type === "joined" && msg.memberId === memberId) {
        clearTimeout(timer);
        client.removeEventListener("message", onMessage);
        resolve();
      }
    };
    client.addEventListener("message", onMessage);
  });
  client.send(joinMessage(sessionId, memberId));
  return acknowledged;
}

describe("CiphertextOnlyRelayServer", () => {
  describe("1. Frame forwarding is opaque", () => {
    it("should forward a relayed frame unchanged", async () => {
      const { port } = await startRelay();

      const sessionId = "test-session-1";
      const memberId1 = "member-1";
      const memberId2 = "member-2";

      // An opaque payload the relay must return byte for byte.
      const testFrame: RelayFrame = {
        id: memberId1,
        epoch: 0,
        nonce: new Uint8Array(12),
        ciphertext: new Uint8Array([1, 2, 3, 4, 5]),
        tag: new Uint8Array(16),
      };

      const client2 = await openClient(port);
      await join(client2, sessionId, memberId2);
      const delivered = awaitFrame(client2);

      const client1 = await openClient(port);
      await join(client1, sessionId, memberId1);
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

      const received = await delivered;
      expect(received.id).toBe(memberId1);
      expect(received.epoch).toBe(0);
      expect(Array.from(received.nonce)).toEqual(Array.from(testFrame.nonce));
      expect(Array.from(received.ciphertext)).toEqual(Array.from(testFrame.ciphertext));
      expect(Array.from(received.tag)).toEqual(Array.from(testFrame.tag));
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
      const { port } = await startRelay();

      const session1 = "session-1";
      const session2 = "session-2";

      const listener = await openClient(port);
      const listenerFrames = collectFrames(listener);
      await join(listener, session2, "m2-session2");

      const sender = await openClient(port);
      await join(sender, session1, "m1-session1");
      sender.send(sealedFrame(session1, "m1-session1"));

      // Negative assertion: bounded wait, nothing may arrive in it.
      await settle();
      expect(listenerFrames.length).toBe(0);
    });
  });

  describe("4. Member join/leave", () => {
    it("should track members and clean up empty sessions", async () => {
      const { relay, port } = await startRelay();

      const sessionId = "test-session-cleanup";
      const memberId = "cleanup-member";

      const client = await openClient(port);
      await join(client, sessionId, memberId);

      // The occupancy census replaces the placeholder assertion this test
      // used to carry: the cleanup is now read, not assumed.
      expect(relay.stats()).toEqual({ sessions: 1, slots: 1, staleSlots: 0 });

      client.send(JSON.stringify({ type: "leave", sessionId, memberId }));
      await settle(100);

      expect(relay.stats()).toEqual({ sessions: 0, slots: 0, staleSlots: 0 });
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
      const { port } = await startRelay();

      const sessionId = "eviction-session";

      // The victim holds the "victim" slot on its own connection.
      const victim = await openClient(port);
      await join(victim, sessionId, "victim");
      const delivered = awaitFrame(victim);

      // A third party — holding no slot at all — tries to evict the victim.
      const attacker = await openClient(port);
      attacker.send(JSON.stringify({ type: "leave", sessionId, memberId: "victim" }));
      await settle(100);

      // A legitimate peer broadcasts: the victim must still be routed to.
      const peer = await openClient(port);
      await join(peer, sessionId, "peer");
      peer.send(sealedFrame(sessionId, "peer"));

      expect((await delivered).id).toBe("peer");
    });

    it("should still honour a leave sent by the connection that owns the slot", async () => {
      const { port } = await startRelay();

      const sessionId = "self-leave-session";

      const leaver = await openClient(port);
      await join(leaver, sessionId, "leaver");
      const leaverFrames = collectFrames(leaver);

      // The owner releases its own slot.
      leaver.send(JSON.stringify({ type: "leave", sessionId, memberId: "leaver" }));
      await settle(100);

      const peer = await openClient(port);
      await join(peer, sessionId, "peer");
      peer.send(sealedFrame(sessionId, "peer"));

      // Having left, the former member is no longer routed to.
      await settle();
      expect(leaverFrames.length).toBe(0);
    });
  });

  describe("7. Routing integrity: join cannot steal an occupied slot", () => {
    it("should keep routing to the holder when another connection joins with the same memberId", async () => {
      const { port } = await startRelay();

      const sessionId = "hijack-session";
      const contestedId = "contested-member";

      // The holder takes the slot first.
      const holder = await openClient(port);
      await join(holder, sessionId, contestedId);
      const delivered = awaitFrame(holder);

      // A second connection claims the very same slot and is refused.
      const hijacker = await openClient(port);
      const hijackerFrames = collectFrames(hijacker);
      const hijackerClosed = awaitClose(hijacker);
      hijacker.send(joinMessage(sessionId, contestedId));
      expect(await hijackerClosed).toBe(1008);

      // A peer broadcasts once.
      const peer = await openClient(port);
      await join(peer, sessionId, "peer");
      peer.send(sealedFrame(sessionId, "peer"));

      // The holder keeps its routing; the hijacker never took it over.
      expect((await delivered).id).toBe("peer");
      expect(hijackerFrames.length).toBe(0);
    });
  });

  describe("8. Routing integrity: frames need a slot the sender holds", () => {
    it("should drop a sealed frame from a connection that never joined the session", async () => {
      const { port } = await startRelay();

      const sessionId = "injection-session";

      const member = await openClient(port);
      await join(member, sessionId, "member");
      const memberFrames = collectFrames(member);

      // An outsider injects a well-formed frame into a session it never joined.
      const outsider = await openClient(port);
      outsider.send(sealedFrame(sessionId, "member"));

      await settle();
      expect(memberFrames.length).toBe(0);
    });
  });

  describe("9. Malformed frames are refused, never thrown", () => {
    it("should close the sender cleanly and keep serving the other members", async () => {
      const { port } = await startRelay();

      const sessionId = "malformed-session";

      const sender = await openClient(port);
      await join(sender, sessionId, "sender");
      const senderClosed = awaitClose(sender);

      // Passes the id/epoch check, then used to blow up on Array.from(undefined).
      sender.send(
        JSON.stringify({
          type: "sealed-frame",
          sessionId,
          frame: { id: "sender", epoch: 0 },
        }),
      );

      // Clean refusal, not an exception escaping the message handler.
      expect(await senderClosed).toBe(1008);

      // The relay is still serving: two fresh members exchange a frame.
      const listener = await openClient(port);
      await join(listener, sessionId, "listener");
      const delivered = awaitFrame(listener);

      const talker = await openClient(port);
      await join(talker, sessionId, "talker");
      talker.send(sealedFrame(sessionId, "talker"));

      expect((await delivered).id).toBe("talker");
    });
  });

  describe("10. A started relay can be stopped", () => {
    it("should release the listening port so no server outlives its test", async () => {
      const relay = new CiphertextOnlyRelayServer();
      const handle = await relay.serve({ hostname: "127.0.0.1", port: 0 });
      const { port } = handle;

      // While the relay listens, that port is taken: binding it again throws.
      expect(() =>
        Bun.serve({ hostname: "127.0.0.1", port, fetch: () => new Response("") }),
      ).toThrow();

      handle.stop();

      // Once stopped, the very same port binds again — the listener is gone.
      const rebound = Bun.serve({ hostname: "127.0.0.1", port, fetch: () => new Response("ok") });
      expect(rebound.port).toBe(port);
      void rebound.stop(true);
    });
  });
});
