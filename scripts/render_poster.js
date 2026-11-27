// Copyright (c) 2026 Sudheer Kumar. SPDX-License-Identifier: AGPL-3.0-only.
// Render the end-to-end architecture poster to PNG (2x) and PDF.  node scripts/render_poster.js
const path = require("path");
const puppeteer = require(process.env.PUPPETEER_PATH || "/opt/npm-tools/node_modules/puppeteer");
(async () => {
  const src = path.resolve(__dirname, "../docs/enterprise/poster/architecture-poster.html");
  const out = path.resolve(__dirname, "../docs/enterprise/poster/RAT-Flea-DevSec-Architecture");
  const b = await puppeteer.launch({ headless: "new", executablePath: process.env.CHROME, args: ["--no-sandbox"] });
  const p = await b.newPage();
  await p.setViewport({ width: 1920, height: 1080, deviceScaleFactor: 2 });
  await p.goto("file://" + src, { waitUntil: "load" });
  const h = await p.evaluate(() => document.body.scrollHeight);
  if (h > 1080) console.warn("content overflows poster height:", h);
  await p.screenshot({ path: out + ".png", clip: { x: 0, y: 0, width: 1920, height: 1080 } });
  await p.pdf({ path: out + ".pdf", width: "1920px", height: "1080px", printBackground: true, pageRanges: "1" });
  await b.close(); console.log("wrote", out + ".png/.pdf");
})();
