# DAKILUHUT — Steal the VFY agent (zkVerify Agent Games Season 01)

Agent endpoint for **DAKILUHUT** (owner: rizal026) in the zkVerify Agent Games,
Season 01 (21 Oct – 21 Nov 2026, 400,000 VFY total, 100,000 per track).

## Track: Steal the VFY

20-turn head-to-head strategy matches, 100 VFY each, highest balance wins.
Every turn the agent answers with one action (HOLD / FORTIFY / EXTRACT N)
plus a Groth16 proof (snarkjs, official vfy-policy circuit) that the action
is the output of its pre-committed strategy for the given game state.

## How it works

```
POST /agent
  │
  ├─ 1. HMAC-SHA256 over the RAW body vs `x-agent-games-signature`
  │     (verified BEFORE JSON parsing; mismatch → HTTP 401)
  ├─ 2. type = "agent-games.preflight.v1"
  │     → signed `{ ok: true, protocolVersion: "v1" }`
  └─ 3. eventId = "steal-the-vfy"
        ├─ idempotency cache (same matchId+turn → cached response)
        ├─ deterministic policy (src/policy.js) → action
        ├─ snarkjs fullProve with vfy-policy.wasm / vfy-policy_final.zkey
        └─ signed JSON response (proof + public_signals nested in policyProof)
```

Fail-closed throughout: malformed envelopes, HMAC failures, and proof
generation failures resolve to HOLD, never to an unproven EXTRACT.

## Strategy

Deterministic thresholds on `(selfBalance, opponentBalance)`, fixed at
commitment time. See `src/policy.js` — `STRATEGY_PARAMS` (8 params + salt).
The Poseidon commitment hash is computed by `npm run commitment` and
registered on the dashboard; it is frozen once matches are paired.

## Run

```
npm install
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET + STRATEGY_SALT
npm start              # listens on $PORT (default 3000)
npm run selftest       # local harness: preflight + mock turns + proof verify
```

## Deploy

Vercel serverless (`api/agent.js`, `bodyParser: false` → raw body for HMAC).
Circuit artifacts are bundled under `circuits/` (official downloads from
https://agentgames.zkverify.io/build).

## Security

Secrets live in env vars only — never committed. `.env` is gitignored.
