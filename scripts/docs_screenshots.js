// Copyright (c) 2026 Sudheer Kumar. SPDX-License-Identifier: AGPL-3.0-only.
// Capture documentation screenshots from the offline demo console (fictional demo tenant).
//   NODE_PATH=<puppeteer install> CHROME=<chrome binary> node scripts/docs_screenshots.js
// Public edition (used by scripts/release/public_export.py): MYELIN_DOCS_EDITION=public writes to
// docs/assets/screenshots-public/, hides the demo banner and rewords the unfiled attestation and evidence mechanisms.
// The capture fails if any of those terms is still visible on screen.
const path = require("path");
const puppeteer = require("puppeteer");
const ROOT = path.resolve(__dirname, "..");
const PUBLIC = process.env.MYELIN_DOCS_EDITION === "public";
const OUT = path.join(ROOT, "docs", "assets", PUBLIC ? "screenshots-public" : "screenshots");
const REWORD = [[/Proprietary (&|and) confidential/gi, "Proprietary"], [/gate attestations?/gi, "gate decision"], [/attestations?/gi, "signature"], [/write-once/gi, "retained"],
  [/legal hold/gi, "retention"], [/signed manifests?/gi, "audit record"], [/provenance manifests?/gi, "audit record"],
  [/Object Lock/g, "object storage"], [/immutable blob/gi, "blob storage"], [/policy digest/gi, "policy version"],
  [/pipeline trust/gi, "pipeline posture"], [/trust level/gi, "posture"], [/in-toto|DSSE/g, "signed"]];
const CHECK = /attestation|write-once|legal hold|signed manifest|object lock|immutable blob|policy digest|pipeline trust|trust level|in-toto|dsse|under NDA|proprietary (&|and) confidential/i;
async function sanitise(p, label) {
  if (!PUBLIC) return;
  const left = await p.evaluate((rw, check) => {
    const banner = document.getElementById("modeBanner"); if (banner) banner.style.display = "none";
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = w.nextNode(); n; n = w.nextNode()) {
      let t = n.nodeValue; for (const [src, flags, to] of rw) t = t.replace(new RegExp(src, flags), to); n.nodeValue = t;
    }
    const m = document.body.innerText.match(new RegExp(check.src, check.flags)); return m ? m[0] : null;
  }, REWORD.map(([r, to]) => [r.source, r.flags, to]), { src: CHECK.source, flags: CHECK.flags });
  if (left) { console.error(`public screenshot ${label}: '${left}' still visible`); process.exit(1); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
const VIEWS = ["overview", "findings", "pipelines", "defence", "posture", "cnapp", "cloud", "kubernetes", "identities", "runtime",
  "compliance", "apptest", "policies", "campaigns", "repos", "integrations", "cra", "crypto"];
(async () => {
  require("fs").mkdirSync(OUT, { recursive: true });
  const b = await puppeteer.launch({ headless: "new", executablePath: process.env.CHROME, args: ["--no-sandbox"] });
  const p = await b.newPage();
  await p.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1.5 });
  await p.goto("file://" + path.join(ROOT, "demo", "offline", "RAT-Flea-DevSec-Demo-Console.html") + "#overview", { waitUntil: "networkidle0" });
  await sleep(1200);
  for (const v of VIEWS) {
    await p.evaluate(h => { location.hash = h; }, v); await sleep(1400);
    await sanitise(p, v);
    await p.screenshot({ path: path.join(OUT, v + ".webp"), type: "webp", quality: 82 });
  }
  for (const [engine, name] of [["sca", "finding-drawer"], ["paths", "attack-path-drawer"]]) {
    await p.evaluate(async e => { closeAll(); const r = await api(`/api/findings?engine=${e}`); const f = r.items.sort((a, c) => c.mrs - a.mrs)[0]; openFinding(f.id); }, engine);
    await sleep(1400);
    await sanitise(p, name);
    await p.screenshot({ path: path.join(OUT, name + ".webp"), type: "webp", quality: 82 });
  }
  await b.close();
})();
