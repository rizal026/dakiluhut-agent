// Vercel serverless entry for DAKILUHUT (Steal the VFY).
// Raw body is required for HMAC verification, so body parsing is disabled
// in vercel.json (`"bodyParser": false` is not a thing for Node functions —
// instead we read the request stream directly and never parse it first).
const { handleRaw } = require("../src/handler");

module.exports = async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks);
  const { status, headers, body } = await handleRaw({
    method: req.method,
    path: (req.url || "/agent").split("?")[0],
    rawBody,
    headers: req.headers,
  });
  res.writeHead(status, headers);
  res.end(body);
};
