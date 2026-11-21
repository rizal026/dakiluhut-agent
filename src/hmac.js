// HMAC-SHA256 helpers for the Agent Games signed transport.
// Every inbound request carries `x-agent-games-signature` = HMAC-SHA256
// (hex) over the RAW request body. Every response must be signed the same
// way (same header, over the raw response body). Verified BEFORE parsing.
const crypto = require("crypto");

const HEADER = "x-agent-games-signature";

function sign(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function verify(secret, rawBody, signature) {
  if (!secret || !signature) return false;
  const expected = sign(secret, rawBody);
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(String(signature).trim().toLowerCase(), "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { HEADER, sign, verify };
