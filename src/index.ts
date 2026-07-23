/**
 * @libre-ai/collab-relay — Ciphertext-only relay for Phase B transport.
 *
 * A WebSocket relay that forwards sealed CRDT frames between members without
 * decryption. The relay is structurally incapable of reading plaintext:
 * - Takes NO key material as input.
 * - NEVER decrypts frame contents (ciphertext remains opaque).
 * - NEVER logs plaintext or sensitive structure.
 *
 * Frames routed by the relay:
 *   { id, epoch, nonce, ciphertext, tag }
 *
 * The relay broadcasts these to all other members in the session, unchanged.
 * Decryption happens only at the destination (if they are an MLS group member).
 */

export { CiphertextOnlyRelayServer, type RelayFrame, type RelayMessage } from "./relay-server";
