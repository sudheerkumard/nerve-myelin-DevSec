// Fixture for engine/myelin_engine/rules/sast/javascript_hardening.yaml (opengrep --test).
const cors = require("cors");
// ruleid: nervve.js.cors-reflect-origin
app.use(cors({ origin: true, credentials: true }));
// ok: nervve.js.cors-reflect-origin
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
app.get("/x", (req, res) => {
  // ruleid: nervve.js.cors-reflect-origin
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  // ruleid: nervve.js.regex-from-input
  const re = new RegExp(req.query.q);
});
// ruleid: nervve.js.postmessage-any-origin
parent.postMessage({ token: t }, "*");
// ok: nervve.js.postmessage-any-origin
parent.postMessage({ token: t }, "https://app.example.com");
function makeResetToken() {
  // ruleid: nervve.js.weak-random-token
  return Math.random().toString(36).slice(2);
}
// ruleid: nervve.js.electron-insecure-webpreferences
new BrowserWindow({ webPreferences: { nodeIntegration: true } });
// ruleid: nervve.js.insecure-tls-version
https.createServer({ minVersion: "TLSv1", key, cert });
