// Print the Poseidon strategy commitment hash (Poseidon of the 8 strategy
// params + salt) so it can be registered on the dashboard. Prints ONLY the
// hash — never the salt or the params.
const { buildPoseidon } = require("circomlibjs");
const { getStrategyConfig } = require("../src/policy");

(async () => {
  const { params, salt } = getStrategyConfig();
  const poseidon = await buildPoseidon();
  const hash = poseidon.F.toObject(poseidon([...params, salt]));
  console.log("commitment (register this on the dashboard):");
  console.log("decimal:", hash.toString());
  console.log("hex: 0x" + hash.toString(16).padStart(64, "0"));
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
