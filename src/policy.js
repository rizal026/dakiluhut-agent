// Deterministic Steal the VFY policy. The circuit (vfy-policy.wasm)
// enforces exactly this decision function over the committed params, so the
// JS policy and the circuit must agree — keep them in sync.
//
// Policy (verified against the circuit with real proofs):
//   selfBalance < params[1]  -> FORTIFY (defend a low balance)
//   opponentBalance < params[2] -> HOLD (opponent nearly empty)
//   otherwise -> EXTRACT params[0]
//
// params[3..7] are unused by the circuit and kept at 0.
// params[0] must be 1..10 (EXTRACT cap). Amounts are integers.
//
// Chosen params for DAKILUHUT: [10, 18, 8, 0, 0, 0, 0, 0]
//   - EXTRACT 10 every open turn (max gain; most of the field runs the
//     published starter default of 8, so 10 is a strict edge over them).
//   - FORTIFY only when our own balance is critically low (< 18).
//   - HOLD only when the opponent is nearly empty (< 8).
// The salt is a fresh random secret (env STRATEGY_SALT) — never the
// published demo salt, never committed, never logged.
const ACTION_CODE = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

function getStrategyConfig() {
  const rawParams = process.env.STEAL_VFY_PARAMS || "10,18,8,0,0,0,0,0";
  const parts = rawParams.split(",").map((x) => BigInt(x.trim()));
  if (parts.length !== 8) {
    throw new Error("STEAL_VFY_PARAMS must have exactly 8 comma-separated integers");
  }
  if (parts[0] < 1n || parts[0] > 10n) {
    throw new Error("params[0] (EXTRACT amount) must be 1..10");
  }
  const saltRaw = process.env.STRATEGY_SALT;
  if (!saltRaw) throw new Error("STRATEGY_SALT env var is required");
  return { params: parts, salt: BigInt(saltRaw) };
}

function decideMove(state, params) {
  const selfBalance = BigInt(state.selfBalance ?? 0);
  const opponentBalance = BigInt(state.opponentBalance ?? 0);
  if (selfBalance < params[1]) return { type: "FORTIFY", amountNum: 0 };
  if (opponentBalance < params[2]) return { type: "HOLD", amountNum: 0 };
  return { type: "EXTRACT", amountNum: Number(params[0]) };
}

module.exports = { ACTION_CODE, getStrategyConfig, decideMove };
