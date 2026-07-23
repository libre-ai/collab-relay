/**
 * Relay server entry point.
 *
 * Starts a ciphertext-only relay on localhost:9000 (or as configured by PORT env var).
 */

import { CiphertextOnlyRelayServer } from "./relay-server";

const hostname = process.env.RELAY_HOST || "0.0.0.0";
const port = parseInt(process.env.RELAY_PORT || "9000", 10);

const relay = new CiphertextOnlyRelayServer();
await relay.serve({ hostname, port });
