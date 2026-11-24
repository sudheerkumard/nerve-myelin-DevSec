// Benchmark: dynamic HTML and code execution sinks
const { exec } = require("child_process");
export function render(el, user) {
  el.innerHTML = user.bio;                                                       // VULN NM-SAST-007
  el.insertAdjacentHTML("beforeend", '<span class="badge">new</span>');          // SAFE constant markup
  el.textContent = user.name;                                                    // SAFE
}
export function calc(expr) { return eval(expr); }                               // VULN NM-SAST-017
export function thumb(file) { exec(`convert ${file} thumb.png`); }              // VULN NM-SAST-018
