export function page(note) {
  return "<h1>" + escapeHtml(note.body) + "</h1>";
}

function escapeHtml(text: string): string {
  return text.replace(/</g, "&lt;");
}

export function unsafe(expr: string) {
  return eval(expr);
}
