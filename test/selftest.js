// Local test harness: starts the agent server on a random port, then
// drives it with a signed preflight + signed mock Steal turns, and verifies
// the returned Groth16 proof locally against the official verification key.
const http = require("http");
const crypto = require("crypto");
const { buildPoseidon } = require("circomlibjs");

const TEST_SECRET = "test-secret-for-local-selftest-only";
process.env.AGENT_GAMES_HMAC_SECRET = TEST_SECRET;
process.env.STRATEGY_SALT = process.env.STRATEGY_SALT || "98765432109876543210";
process.env.STEAL_VFY_PARAMS = process.env.STEAL_VFY_PARAMS || "10,18,8,0,0,0,0,0";

const { handleRaw } = require("../src/handler");

function sign(rawBody) {
  return crypto.createHmac("sha256", TEST_SECRET).update(rawBody).digest("hex");
}

async function post(port, path, obj, { badSig = false } = {}) {
  const raw = Buffer.from(JSON.stringify(obj), "utf8");
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, path, method: "POST", headers: { "content-type": "application/json", "x-agent-games-signature": badSig ? "00".repeat(32) : sign(raw), "content-length": raw.length } },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
      }
    );
    req.on("error", reject);
    req.end(raw);
  });
}

(async () => {
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const { status, headers, body } = await handleRaw({ method: req.method, path: req.url.split("?")[0], rawBody: Buffer.concat(chunks), headers: req.headers });
      res.writeHead(status, headers);
      res.end(body);
    });
  });
  await new Promise((r) => server.listen(0, r));
  const port = server.address().port;
  console.log("selftest server on", port);

  // 1. Preflight
  const pre = await post(port, "/agent", { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  console.log("preflight:", pre.status, pre.body);
  if (pre.status !== 200) throw new Error("preflight failed");
  const preSigOk = crypto.timingSafeEqual(
    Buffer.from(pre.headers["x-agent-games-signature"] || "", "utf8"),
    Buffer.from(sign(Buffer.from(pre.body, "utf8")), "utf8")
  );
  console.log("preflight response signature valid:", preSigOk);

  // 2. Bad signature must 401
  const bad = await post(port, "/agent", { type: "agent-games.preflight.v1" }, { badSig: true });
  console.log("bad-signature request status (expect 401):", bad.status);

  // 3. Mock Steal turns (state chosen to exercise each policy branch)
  const poseidon = await buildPoseidon();
  const params = [10n, 18n, 8n, 0n, 0n, 0n, 0n, 0n];
  const salt = BigInt(process.env.STRATEGY_SALT);
  const commitment = poseidon.F.toObject(poseidon([...params, salt])).toString();
  const matchId = "9f4e1b2a-1111-2222-3333-444455556666";

  const snarkjs = require("snarkjs");
  const vk = await snarkjs.zKey.exportVerificationKey(require("path").join(__dirname, "..", "circuits", "vfy-policy_final.zkey"));

  const turns = [
    { turn: 1, self: "100", opp: "100", expect: "EXTRACT", amount: 10 }, // open -> extract max
    { turn: 2, self: "12", opp: "100", expect: "FORTIFY", amount: undefined }, // self < 18 -> fortify
    { turn: 3, self: "100", opp: "5", expect: "HOLD", amount: undefined }, // opp < 8 -> hold
  ];
  for (const t of turns) {
    const envelope = {
      protocolVersion: "v1", eventId: "steal-the-vfy", mode: "practice",
      matchId, turn: t.turn, issuedAt: new Date().toISOString(),
      deadlineAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      state: { selfBalance: t.self, opponentBalance: t.opp, selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
      strategyCommitment: { hash: "0x" + BigInt(commitment).toString(16).padStart(64, "0") },
      resolverVersion: "v1", nonce: "test-nonce-" + t.turn,
    };
    const r = await post(port, "/agent", envelope);
    const parsed = JSON.parse(r.body);
    console.log(`turn ${t.turn}: status ${r.status}, action ${JSON.stringify(parsed.action)}, expect ${t.expect}`);
    if (parsed.action.type !== t.expect) throw new Error(`turn ${t.turn}: wrong action`);
    if (t.amount !== undefined && parsed.action.amount !== t.amount) throw new Error(`turn ${t.turn}: wrong amount`);
    if (t.amount === undefined && "amount" in parsed.action) throw new Error(`turn ${t.turn}: amount must be omitted`);
    const proofOk = await snarkjs.groth16.verify(vk, parsed.policyProof.public_signals, parsed.policyProof.proof);
    console.log(`  proof verifies: ${proofOk}, publicSignals: ${JSON.stringify(parsed.policyProof.public_signals)}`);
    if (!proofOk) throw new Error(`turn ${t.turn}: proof does NOT verify`);
    if (parsed.policyProof.publicInputsHash !== require("../src/prover").computePublicInputsHash({
      commitment, matchId, turn: t.turn, selfBalance: t.self, opponentBalance: t.opp,
      actionCode: { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n }[parsed.action.type], amount: parsed.action.amount || 0,
    })) throw new Error(`turn ${t.turn}: publicInputsHash mismatch`);
    console.log("  publicInputsHash matches");
  }

  // 4. Idempotency: resend turn 1, expect identical idempotencyKey
  const again = await post(port, "/agent", {
    protocolVersion: "v1", eventId: "steal-the-vfy", mode: "practice",
    matchId, turn: 1, issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    state: { selfBalance: "100", opponentBalance: "100", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: "0x" + BigInt(commitment).toString(16).padStart(64, "0") },
    resolverVersion: "v1", nonce: "test-nonce-1-resend",
  });
  const first = JSON.parse((await post(port, "/agent", {
    protocolVersion: "v1", eventId: "steal-the-vfy", mode: "practice",
    matchId, turn: 1, issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    state: { selfBalance: "100", opponentBalance: "100", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: "0x" + BigInt(commitment).toString(16).padStart(64, "0") },
    resolverVersion: "v1", nonce: "test-nonce-1",
  })).body);
  console.log("idempotencyKey stable across resend:", JSON.parse(again.body).idempotencyKey === first.idempotencyKey);

  console.log("SELFTEST PASSED");
  server.close();
  process.exit(0);
})().catch((e) => {
  console.error("SELFTEST FAILED:", e);
  process.exit(1);
});
