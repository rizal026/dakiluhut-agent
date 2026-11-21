// Local Node server for DAKILUHUT (Steal the VFY). Listens on $PORT (3000).
const http = require("http");
const { handleRaw } = require("./handler");

const PORT = Number(process.env.PORT || 3000);

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const rawBody = Buffer.concat(chunks);
    try {
      const { status, headers, body } = await handleRaw({
        method: req.method,
        path: req.url.split("?")[0],
        rawBody,
        headers: req.headers,
      });
      res.writeHead(status, headers);
      res.end(body);
    } catch (err) {
      console.error("server error:", err);
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "internal error" }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`DAKILUHUT agent listening on :${PORT} (POST /agent, GET /health)`);
  if (!process.env.AGENT_GAMES_HMAC_SECRET) {
    console.warn("WARNING: AGENT_GAMES_HMAC_SECRET is not set — preflight will fail until the real secret is configured.");
  }
  if (!process.env.STRATEGY_SALT) {
    console.warn("WARNING: STRATEGY_SALT is not set — turns will fail closed to HOLD.");
  }
});
