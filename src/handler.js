// Request pipeline for the Steal the VFY agent endpoint.
//   POST /agent  (HMAC-verified, fail-closed to HOLD)
//   GET  /health -> { ok: true, protocolVersion: "v1" }
const crypto = require("crypto");
const hmac = require("./hmac");
const { ACTION_CODE, getStrategyConfig, decideMove } = require("./policy");
const { computePublicInputsHash, proveTurn } = require("./prover");

const CIRCUIT_VERSION = "v1";

// In-memory idempotency cache: same matchId+turn -> same response object.
// The idempotencyKey itself is deterministic (derived from matchId+turn),
// so a resend is deduped by the platform even across cold starts.
const responseCache = new Map();

// Deterministic UUID from matchId+turn (UUIDv5-style formatting of a
// keccak256 digest — no randomness, stable across resends and restarts).
function deterministicIdempotencyKey(matchId, turn) {
  const { keccak256 } = require("js-sha3");
  const digest = keccak256(Buffer.from(`${matchId}:${turn}`, "utf8"));
  const h = digest.slice(0, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

function failHold(matchId, turn) {
  // Fail-closed turn response WITHOUT a proof: the platform treats it as
  // HOLD with no proof (turn scores 0, not -2). Still signed + idempotent.
  return {
    matchId,
    turn,
    action: { type: "HOLD" },
    // No proof fields at all: the platform treats a missing proof as HOLD
    // with no proof (turn scores 0, not -2). A null proof might fail
    // schema validation, so the fields are omitted, not nulled.
    policyProof: { circuitVersion: CIRCUIT_VERSION },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: deterministicIdempotencyKey(matchId, turn),
  };
}

async function handleTurn(payload) {
  const { matchId, turn, state, strategyCommitment } = payload;
  const cacheKey = `${matchId}:${turn}`;
  if (responseCache.has(cacheKey)) return responseCache.get(cacheKey);

  let response;
  try {
    const { params, salt } = getStrategyConfig();
    const move = decideMove(state || {}, params);
    const actionCode = ACTION_CODE[move.type];
    const amount = move.amountNum;

    const commitment = strategyCommitment && strategyCommitment.hash
      ? BigInt(strategyCommitment.hash).toString()
      : null;
    if (!commitment) throw new Error("missing strategyCommitment.hash in envelope");

    const publicInputsHash = computePublicInputsHash({
      commitment,
      matchId,
      turn,
      selfBalance: state.selfBalance,
      opponentBalance: state.opponentBalance,
      actionCode,
      amount,
    });

    const { proof, publicSignals } = await proveTurn({
      commitment,
      matchId,
      turn,
      selfBalance: state.selfBalance,
      opponentBalance: state.opponentBalance,
      actionCode,
      amount,
      salt,
      params,
    });

    const actionObj = move.type === "EXTRACT"
      ? { type: "EXTRACT", amount }
      : { type: move.type }; // HOLD / FORTIFY omit amount entirely

    response = {
      matchId,
      turn,
      action: actionObj,
      policyProof: {
        circuitVersion: CIRCUIT_VERSION,
        proof,
        public_signals: publicSignals,
        publicInputsHash,
      },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: deterministicIdempotencyKey(matchId, turn),
    };
  } catch (err) {
    console.error("turn failed, failing closed to HOLD:", err && err.message ? err.message : err);
    response = failHold(matchId, turn);
  }

  responseCache.set(cacheKey, response);
  return response;
}

function handlePreflight() {
  return { ok: true, protocolVersion: "v1" };
}

function handleHealth() {
  return { ok: true, protocolVersion: "v1" };
}

// Raw-body handler shared by the local server and the Vercel entry.
// Returns { status, headers, body } — body is a JSON string.
async function handleRaw({ method, path: reqPath, rawBody, headers }) {
  if (method === "GET" && (reqPath === "/health" || reqPath === "/")) {
    return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify(handleHealth()) };
  }
  if (method !== "POST") {
    return { status: 405, headers: { "content-type": "application/json" }, body: JSON.stringify({ error: "method not allowed" }) };
  }

  const secret = process.env.AGENT_GAMES_HMAC_SECRET || "";
  const signature = headers["x-agent-games-signature"] || headers["X-Agent-Games-Signature"];
  if (!hmac.verify(secret, rawBody, signature)) {
    return { status: 401, headers: { "content-type": "application/json" }, body: JSON.stringify({ error: "bad signature" }) };
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return { status: 400, headers: { "content-type": "application/json" }, body: JSON.stringify({ error: "invalid json" }) };
  }

  let result;
  if (payload && payload.type === "agent-games.preflight.v1") {
    result = handlePreflight();
  } else if (payload && payload.eventId === "steal-the-vfy") {
    result = await handleTurn(payload);
  } else {
    return { status: 400, headers: { "content-type": "application/json" }, body: JSON.stringify({ error: "unknown envelope" }) };
  }

  const body = JSON.stringify(result);
  return {
    status: 200,
    headers: {
      "content-type": "application/json",
      [hmac.HEADER]: hmac.sign(secret, Buffer.from(body, "utf8")),
    },
    body,
  };
}

module.exports = { handleRaw, handleTurn, handlePreflight, deterministicIdempotencyKey };
