// Fixture for engine/myelin_engine/rules/sast/javascript.yaml (opengrep --test). Not executed.
const express = require("express");
const child_process = require("child_process");
const fs = require("fs");
const axios = require("axios");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const app = express();

app.get("/user", (req, res) => {
  const id = req.query.id;
  // ruleid: nervve.js.sql-injection
  db.query("SELECT * FROM users WHERE id = " + id);
  // ruleid: nervve.js.sql-injection
  db.query(`SELECT * FROM users WHERE id = ${id}`);
  // ok: nervve.js.sql-injection
  db.query("SELECT * FROM users WHERE id = ?", [id]);
  // ok: nervve.js.sql-injection
  db.query("SELECT * FROM users WHERE id = " + parseInt(id, 10));
  res.json({ ok: true });
});

app.post("/ping", function (req, res) {
  // ruleid: nervve.js.command-injection
  child_process.exec("ping -c 1 " + req.body.host);
  // ok: nervve.js.command-injection
  child_process.execFile("ping", ["-c", "1", req.body.host]);
  res.end();
});

app.post("/calc", (req, res) => {
  // ruleid: nervve.js.code-injection
  res.json({ v: eval(req.body.expr) });
});

app.get("/file", (req, res) => {
  // ruleid: nervve.js.path-traversal
  fs.readFile("/srv/files/" + req.query.name, (e, d) => res.send(d));
  // ok: nervve.js.path-traversal
  fs.readFile("/srv/files/" + path.basename(req.query.name), (e, d) => res.send(d));
});

app.get("/fetch", async (req, res) => {
  // ruleid: nervve.js.ssrf
  const r = await axios.get(req.query.url);
  // ok: nervve.js.ssrf
  await axios.get("https://api.example.com/status");
  res.json(r.data);
});

app.get("/go", (req, res) => {
  // ruleid: nervve.js.open-redirect
  res.redirect(req.query.next);
});

app.get("/hello", (req, res) => {
  // ruleid: nervve.js.reflected-xss
  res.send("<h1>Hello " + req.query.name + "</h1>");
  // ok: nervve.js.reflected-xss
  res.send("<h1>Hello " + escape(req.query.name) + "</h1>");
});

app.post("/login", async (req, res) => {
  // ruleid: nervve.js.nosql-injection
  const u = await User.findOne({ user: req.body.user, pass: req.body.pass });
  // ok: nervve.js.nosql-injection
  const v = await User.findOne({ user: String(req.body.user) });
  res.json({ u, v });
});

function render() {
  const q = location.hash.substring(1);
  // ruleid: nervve.js.dom-xss
  document.getElementById("out").innerHTML = q;
  // ok: nervve.js.dom-xss
  document.getElementById("out").textContent = q;
}

// ruleid: nervve.js.tls-verification-disabled
const agent = new https.Agent({
  rejectUnauthorized: false,
});

function hash(pw) {
  // ruleid: nervve.js.weak-crypto
  return crypto.createHash("md5").update(pw).digest("hex");
}

function ok(pw) {
  // ok: nervve.js.weak-crypto
  return crypto.createHash("sha256").update(pw).digest("hex");
}


// --- framework configuration
const session = require("express-session");
// ruleid: nervve.js.session-cookie-flags-missing, nervve.js.hardcoded-session-secret
app.use(session({ secret: "keyboard cat", resave: false }));
// ok: nervve.js.session-cookie-flags-missing
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: true, httpOnly: true } }));
// ruleid: nervve.js.template-autoescape-disabled
swig.setDefaults({ autoescape: false });

function allocations(db, userId, threshold) {
  // ruleid: nervve.js.nosql-where-injection
  return db.find({ $where: "this.userId == " + userId + " && this.stocks > " + threshold });
}

app.post("/login", (req, res) => {
  // ruleid: nervve.js.log-injection
  console.log("login attempt for " + req.body.userName);
  // ok: nervve.js.log-injection
  console.log("login attempt", JSON.stringify(req.body.userName));
});
