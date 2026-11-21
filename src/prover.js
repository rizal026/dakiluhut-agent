// Groth16 proving for Steal the VFY (official vfy-policy circuit) and the
// published publicInputsHash (keccak256 over 8 fields, 32-byte big-endian).
const path = require("path");
const { keccak256 } = require("js-sha3");

const WASM_PATH = path.join(__dirname, "..", "circuits", "vfy-policy.wasm");
const ZKEY_PATH = path.join(__dirname, "..", "circuits", "vfy-policy_final.zkey");

// Lazy-load snarkjs: requiring it is slow (tens of seconds on a cold
// process), and preflight/health requests must not pay that cost.
let snarkjsPromise = null;
function getSnarkjs() {
  if (!snarkjsPromise) snarkjsPromise = Promise.resolve().then(() => require("snarkjs"));
  return snarkjsPromise;
}

function matchIdToBigInt(matchId) {
  const hex = String(matchId).replace(/^0x/i, "").replace(/-/g, "");
  return BigInt("0x" + hex);
}

// keccak256 over 8 fields, each 32-byte big-endian, in the published order:
// commitment, matchId, turn, selfBalance, opponentBalance, action code,
// amount, circuitVersion ("v1" = 1). Returns 0x-hex.
function computePublicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, actionCode, amount }) {
  const fields = [
    BigInt(commitment),
    matchIdToBigInt(matchId),
    BigInt(turn),
    BigInt(selfBalance),
    BigInt(opponentBalance),
    BigInt(actionCode),
    BigInt(amount),
    1n, // circuitVersion "v1"
  ];
  const packed = Buffer.concat(
    fields.map((f) => {
      const hex = f.toString(16).padStart(64, "0");
      return Buffer.from(hex, "hex");
    })
  );
  return "0x" + keccak256(packed);
}

async function proveTurn({ commitment, matchId, turn, selfBalance, opponentBalance, actionCode, amount, salt, params }) {
  const snarkjs = await getSnarkjs();
  const circuitInput = {
    commitment: BigInt(commitment).toString(),
    matchId: matchIdToBigInt(matchId).toString(),
    turnNumber: String(turn),
    selfBalance: String(selfBalance),
    opponentBalance: String(opponentBalance),
    action: String(actionCode),
    amount: String(amount),
    circuitVersion: "1",
    salt: BigInt(salt).toString(),
    strategyParams: params.map((p) => BigInt(p).toString()),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

module.exports = { computePublicInputsHash, proveTurn, matchIdToBigInt };
