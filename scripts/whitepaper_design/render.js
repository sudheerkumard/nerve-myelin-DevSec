// Renders docs/whitepaper/designed/index.html to PDF and fails if any page's content overflows its A4 frame.
// Copyright (c) 2026 Sudheer Kumar. SPDX-License-Identifier: AGPL-3.0-only.
// Usage: NODE_PATH=<puppeteer install> CHROME=<chrome binary> node scripts/whitepaper_design/render.js [out.pdf]
const path = require("path");
const puppeteer = require("puppeteer");
const ROOT = path.resolve(__dirname, "..", "..");
const SRC = "file://" + path.join(ROOT, "docs", "whitepaper", "designed", "index.html");
const OUT = process.argv[2] || path.join(ROOT, "docs", "whitepaper", "RAT-Flea-DevSec-Whitepaper.pdf");
(async () => {
  const b = await puppeteer.launch({ headless: "new", executablePath: process.env.CHROME || undefined, args: ["--no-sandbox"] });
  const p = await b.newPage();
  await p.emulateMediaFeatures([{ name: "prefers-reduced-motion", value: "reduce" }]);
  await p.setViewport({ width: 1000, height: 1400 });
  await p.goto(SRC, { waitUntil: "networkidle0" });
  await p.evaluate(() => document.fonts.ready);
  const problems = await p.evaluate(() => {
    const out = [];
    document.querySelectorAll("section.page").forEach(pg => {
      const frame = pg.getBoundingClientRect();
      pg.querySelectorAll(".inner *, .inner").forEach(el => {
        const r = el.getBoundingClientRect();
        if (r.width && (r.bottom > frame.bottom - 14 || r.right > frame.right + 0.5)) out.push(`page ${pg.dataset.page}: ${el.tagName}.${el.className} overflows (${Math.round(r.bottom - frame.bottom)}px)`);
      });
      const inner = pg.querySelector(".inner");
      if (inner && inner.scrollHeight > inner.clientHeight + 2) out.push(`page ${pg.dataset.page}: content taller than its frame by ${inner.scrollHeight - inner.clientHeight}px`);
    });
    document.querySelectorAll("img").forEach(i => { if (!i.complete || !i.naturalWidth) out.push("image not loaded: " + i.getAttribute("src")); });
    return [...new Set(out)].slice(0, 40);
  });
  if (problems.length) { console.error("LAYOUT PROBLEMS:\n  " + problems.join("\n  ")); }
  await p.pdf({ path: OUT, preferCSSPageSize: true, printBackground: true });
  await b.close();
  console.log("wrote", OUT);
  process.exit(problems.length ? 2 : 0);
})();
