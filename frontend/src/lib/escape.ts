/**
 * HTML-escaping helpers (defense in depth against stored XSS,
 * GHSA-xwm2-h7v2-47f2). Any user-controlled value interpolated into an
 * innerHTML template string MUST go through escapeHtml; URLs placed in an
 * href/src attribute MUST go through safeUrl first.
 */

/** Escape the five HTML-significant characters for safe interpolation. */
export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Return url only if it is a safe http(s) or site-relative URL, otherwise
 * an empty string. Blocks javascript:, data:, and other dangerous schemes.
 * The result is still meant to be passed through escapeHtml when placed in
 * an attribute.
 */
export function safeUrl(url: unknown): string {
  const raw = String(url ?? "").trim();
  if (raw === "") return "";
  if (raw.startsWith("/") && !raw.startsWith("//")) return raw; // site-relative
  if (/^https?:\/\//i.test(raw)) return raw;
  return "";
}
