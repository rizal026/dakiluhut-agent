// Probe vfy-policy.wasm input signal names via the circom_runtime witness
// calculator oracle. A candidate name is FOUND when a witness attempt with
// {[name]: ["1"]} fails with "Not all inputs have been set" (scalar exists)
// or "Not enough values for input signal" (array signal exists). ABSENT when
// the error is "Too many values for input signal" or "Signal <name> not found".
// Method: witness-calculator oracle (same technique as the public PROBE.md
// write-up); candidate list is our own, extended with the strategy-param
// names the earlier probe never tried.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const WASM = path.join(ROOT, "circuits", "vfy-policy.wasm");

const BASE = [
  "strategyParams", "params", "policyParams", "thresholds", "threshold",
  "weights", "coefficients", "strategyValues", "policyValues", "strategy",
  "policy", "param", "p", "s", "a", "b", "x", "w", "k", "c",
  "policyThresholds", "strategyThresholds", "actionThresholds",
  "balanceThresholds", "extractThreshold", "fortifyThreshold",
  "minBalance", "maxBalance", "oppThreshold", "selfThreshold",
  "extractWhen", "fortifyWhen", "holdThreshold", "aggression", "defense",
  "risk", "edge", "margin", "spread", "diff", "gap", "ratio", "pct",
  "percent", "factor", "multiplier", "limit", "cap", "floor", "ceil",
  "lo", "hi", "minExtract", "maxExtract", "min", "max",
  "privateParams", "secretParams", "policyInputs", "strategyInputs",
  "commitmentParams", "gameParams", "matchParams", "turnParams",
  "theta", "alpha", "beta", "gamma", "delta",
];
const INDEXED = [];
for (const prefix of ["p", "param", "threshold", "s", "t", "w", "in", "input", "private", "value", "k", "c", "e", "f", "h", "a", "b", "x", "y", "z", "strategyParam", "policyParam", "thresholdParam"]) {
  for (let i = 0; i < 8; i++) INDEXED.push(`${prefix}${i}`);
}
const CANDIDATES = [...new Set([...BASE, ...INDEXED])];

const builder = (
  await import(
    pathToFileURL(path.join(ROOT, "node_modules", "circom_runtime/js/witness_calculator.js")).href
  )
).default;

const buf = fs.readFileSync(WASM);
const wc = await builder(buf);
const ex = wc.instance.exports;
console.log("total scalar inputs (getInputSize):", ex.getInputSize());
console.log("witness size:", ex.getWitnessSize());

const found = [];
const foundArray = [];
for (const name of CANDIDATES) {
  try {
    await wc.calculateWitness({ [name]: ["1"] }, true);
    found.push(name); // no error at all — exists (impossible for 17-input circuit, but record it)
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    if (/Not all inputs have been set/.test(msg)) found.push(name);
    else if (/Not enough values for input signal/.test(msg)) foundArray.push(name);
    else if (/Too many values for input signal/.test(msg) || /Signal .* not found/.test(msg)) { /* absent */ }
    else console.log(`  ? ${name}: unexpected error: ${msg.slice(0, 120)}`);
  }
}
console.log("FOUND scalar:", JSON.stringify(found));
console.log("FOUND array:", JSON.stringify(foundArray));
process.exit(0);
