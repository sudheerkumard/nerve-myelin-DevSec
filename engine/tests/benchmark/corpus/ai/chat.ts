// chat UI: LLM output handling benchmark
export function render(el: HTMLElement, completion: { text: string }) {
  el.innerHTML = completion.text;                                   // VULN NM-AI-010
  el.textContent = completion.text;                                 // SAFE text, not HTML
}
export function prompt(req: any) {
  return [{ role: "user", content: `Summarise ${req.body.text}` }];  // VULN NM-AI-014
}
