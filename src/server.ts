/**
 * Relay server entry point.
 *
 * Starts a ciphertext-only relay on localhost:9000 (or as configured by PORT env var).
 */

import { CiphertextOnlyRelayServer } from "./relay-server";

/** Read a capacity ceiling from the environment; absent means "keep the default". */
function envInteger(name: string): number | undefined {
  const raw = process.env[name];
  return raw === undefined ? undefined : Number.parseInt(raw, 10);
}

const hostname = process.env.RELAY_HOST || "0.0.0.0";
const port = parseInt(process.env.RELAY_PORT || "9000", 10);

// Capacity ceilings are an operator's knob, not a code edit. A value that is
// not a positive whole number fails at startup (RangeError) rather than being
// silently ignored, which would leave the relay running on a ceiling nobody
// chose.
const relay = new CiphertextOnlyRelayServer({
  maxSessions: envInteger("RELAY_MAX_SESSIONS"),
  maxMembersPerSession: envInteger("RELAY_MAX_MEMBERS_PER_SESSION"),
});

await relay.serve({ hostname, port });
