"use strict";

// Outbound secret/PII redaction shared by two consumers with DIFFERENT jobs:
//   - the in-app runner (lib/runner/secret-redaction.ts re-exports
//     redactSensitiveText / containsUnsendableSecret) — scrubs tool OUTPUT, where
//     casting a wide net (and some over-redaction) is the right trade; and
//   - the CLI review suite (scripts/review/privacy-guard.mjs re-exports
//     scrubPrompt / totalRedactions) — scrubs source CONTEXT sent for review,
//     where precision matters so it doesn't blank `tokens`/`keyboard` out of a diff.
//
// They are NOT the same behavior. What they DO share — and where a fix must land
// once — is the set of provider-key SHAPES (PROVIDER_REDACTORS below). The keyword
// matching is intentionally tuned per job: redactSensitiveText keeps the runner's
// broad substring matching; scrubPrompt keeps the precise whole-token matching.
//
// CommonJS (`.cjs`) on purpose: a .cjs can be `import`ed by the ESM `.mjs` review
// scripts AND `require()`d by the app's compiled-to-CommonJS code (incl. the smoke
// boundary checks) on Node 20 — neither can load an ESM `.mjs` here.

// A private-key marker means the content must never be SENT for review. Two
// alternatives, so an INCOMPLETE block is caught just like a complete one:
//   1. a leading `-----BEGIN [algo ]*PRIVATE KEY[ BLOCK]` opener — matched even when
//      the paste is cut short BEFORE the opener's own closing dashes (no footer); and
//   2. any `[algo ]?PRIVATE KEY[ BLOCK]-----` marker carrying trailing dashes, which
//      also covers a complete opener line and a stray END footer.
// `[A-Z0-9 ]*` is a single star over a class with a literal `PRIVATE KEY` suffix —
// linear, no nested quantifier (no ReDoS). Assembled from PEM_MARKER + the dashes so
// the blocked fragment never appears contiguously in THIS file — otherwise the review
// suite would block its own security module.
const PEM_MARKER = "PRIVATE " + "KEY";
const DASH5 = "-----";
const PEM_BLOCK_RE = new RegExp(
  `${DASH5}BEGIN [A-Z0-9 ]*${PEM_MARKER}(?: BLOCK)?|(?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?${PEM_MARKER}(?: BLOCK)?${DASH5}`
);

// ============================================================================
// SHARED provider-key shapes — used by BOTH paths. A new key format added here
// is caught by the runner AND the review suite at once.
// ============================================================================
const PROVIDER_REDACTORS = [
  // PEM private-key, redacted in place (for redact-only callers; scrubPrompt
  // blocks before reaching here). Full BEGIN...END, a BEGIN block truncated before
  // its END (to end of text), an opener cut short before its OWN closing dashes
  // (`(?:${DASH5})?` — no footer at all), and a stray END marker.
  // `(?: BLOCK)?` covers the PGP form, whose marker carries a trailing ` BLOCK`
  // before the closing dashes, so the fallback redactor masks the same keys
  // containsUnsendableSecret flags. (Marker text is never written contiguously in
  // this file, or the review suite's own privacy guard would block it.)
  {
    type: "private-key",
    re: new RegExp(
      `${DASH5}BEGIN [A-Z0-9 ]*${PEM_MARKER}(?: BLOCK)?(?:${DASH5})?[\\s\\S]*?(?:${DASH5}END [A-Z0-9 ]*${PEM_MARKER}(?: BLOCK)?${DASH5}|$)`,
      "g"
    ),
    repl: "[redacted:private-key]",
  },
  { type: "private-key", re: new RegExp(`${DASH5}END [A-Z0-9 ]*${PEM_MARKER}(?: BLOCK)?${DASH5}`, "g"), repl: "[redacted:private-key]" },
  { type: "aws-access-key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, repl: "[redacted:aws-access-key]" },
  { type: "api-key", re: /\bsk-[A-Za-z0-9_-]{16,}\b/g, repl: "[redacted:api-key]" }, // OpenAI/DeepSeek
  { type: "api-key", re: /\bgsk_[A-Za-z0-9_-]{16,}\b/g, repl: "[redacted:api-key]" }, // Groq
  { type: "stripe-key", re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g, repl: "[redacted:stripe-key]" },
  // GitHub tokens — underscores allowed in the body (the runner's threshold).
  { type: "github-token", re: /\b(?:gh[posru]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{22,})\b/g, repl: "[redacted:github-token]" },
  { type: "google-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, repl: "[redacted:google-key]" },
  { type: "slack-token", re: /\b(?:xox[baprs]|xapp)-[0-9A-Za-z-]{10,}\b/g, repl: "[redacted:slack-token]" },
  { type: "jwt", re: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g, repl: "[redacted:jwt]" },
  // Credentials embedded in a connection-string URL (user:pass@ or token@). `?`/`#`
  // excluded so a query-string `@` isn't misread as userinfo. Scheme length is bounded
  // ({0,40}) so a long dotted non-URL string (`a.a.a…`) can't make this super-linear.
  {
    type: "url-credentials",
    re: /\b([a-z][a-z0-9+.-]{0,40}:\/\/)(?:[^\s:@/?#]*:[^\s@/?#]+|[^\s@/?#]+)@/gi,
    repl: "$1[redacted:credentials]@",
  },
];

/**
 * Apply an ordered list of `{ type, re, repl }` redactors to `text`, calling
 * `bump(type)` once per match so callers can count redactions per type. Returns the
 * redacted string. `repl` may reference captured groups (`$1`) to keep a prefix.
 */
function applyRedactors(text, redactors, bump) {
  let safe = text;
  for (const { type, re, repl } of redactors) {
    safe = safe.replace(re, (...args) => {
      bump(type);
      // re-run $1/$2 by hand so a redactor can keep a captured prefix.
      return repl.replace(/\$(\d)/g, (_, d) => args[Number(d)] ?? "");
    });
  }
  return safe;
}

// ============================================================================
// PRECISE layer — scrubPrompt only (review context; must not over-redact code).
// ============================================================================
const CLI_REDACTORS = [
  // Bearer token: short tokens only inside an explicit Authorization header (the
  // header name may be a quoted JSON key, `"Authorization": "Bearer ..."`); a bare
  // `Bearer <token>` needs 20+ so prose isn't masked.
  { type: "bearer-token", re: /\b((?:Proxy-)?Authorization["']?\s*:\s*["']?)Bearer\s+[A-Za-z0-9._~+/-]{6,}={0,2}/gi, repl: "$1Bearer [redacted:token]" },
  { type: "bearer-token", re: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}/gi, repl: "Bearer [redacted:token]" },
  // HTTP Basic auth — short payloads only in an explicit Authorization header.
  { type: "basic-auth", re: /\b((?:Proxy-)?Authorization["']?\s*:\s*["']?)Basic\s+[A-Za-z0-9+/]{4,}={0,2}/gi, repl: "$1Basic [redacted:credentials]" },
  { type: "basic-auth", re: /\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}/gi, repl: "Basic [redacted:credentials]" },
  // Cookie / Set-Cookie values; the `=` requirement avoids stripping prose and the
  // value stops at a quote / `; , }` so same-line code stays visible.
  { type: "cookie", re: /\b((?:Set-)?Cookie["']?\s*:\s*["']?)[^\n]*=[^\n"';,}]+/gi, repl: "$1[redacted:cookie]" },
  // --- personal data (PII) ---
  { type: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, repl: "[redacted:email]" },
  { type: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g, repl: "[redacted:ssn]" },
  { type: "home-path", re: /([A-Za-z]:\\{1,2}Users\\{1,2})[^\\/\s"']+/g, repl: "$1[redacted:user]" },
  { type: "home-path", re: /(\/(?:home|Users)\/)[^/\s"']+/g, repl: "$1[redacted:user]" },
  // Connection string: the value is semicolon-delimited (`AccountName=x;AccountKey=y`),
  // so it must be captured WHOLE — not by the generic assignment rule, which stops at
  // the first `;` and would leave the secret-bearing tail (`AccountKey=y`) visible.
  {
    type: "connection-string",
    // Quoted branches consume escaped quotes (`\"`) so a serialized JSON connection
    // string is captured as ONE value — otherwise it would stop at the first `\"` and
    // leave later `;`-delimited secret fields visible.
    re: /\b(connection[_-]?string["']?\s*[:=]\s*)("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|[^\n]+)/gi,
    repl: "$1[redacted:connection-string]",
  },
];

// Generic `<secret-name> <sep> <value>` assignments — the backstop for unknown
// secret formats. The NAME matching is whole-token (lookarounds, not substrings) so
// ordinary code (`keyboard`, `tokens`, `KEYWORDS`) is left intact. The VALUE is
// captured broadly (quoted literal, brace expression, or unquoted run) and then
// classified by shouldRedactValue() — distinguishing a secret literal from benign
// code (a type annotation, a member/expression reference, or a React `key={...}`
// prop) can't be done in the regex alone, because e.g. `apiKey: string` (a type) and
// `apiKey: realsecret` (a literal) are the same shape. Named ASSIGNMENT_RE (not
// *_SECRET_RE) so it doesn't redact its own definition.
const VALUE = `("(?:[^"\\\\]|\\\\.)*"|'(?:[^'\\\\]|\\\\.)*'|\\{[^{}\\n]*\\}|[^\\n,;)}]+)`;
// `CREDENTIAL` (singular) is included whole-token: it matches `CREDENTIAL=` /
// `credential:` but the `(?![A-Za-z])` boundary excludes the plural lowercase
// `credentials` fetch option, which must stay visible for review.
const ASSIGNMENT_RE = new RegExp(
  `(?<![A-Za-z])((?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)[0-9]*(?:_[A-Za-z0-9]+)*(?![A-Za-z])["']?\\s*[:=]\\s*)${VALUE}`,
  "gi"
);
// ALL-CAPS env suffixes the case-insensitive ASSIGNMENT_RE can't carry without
// over-matching lowercase prose. `["']?` covers a quoted JSON key. CREDENTIALS lives
// here (ALL-CAPS only) rather than in ASSIGNMENT_RE so the lowercase `credentials`
// fetch option (`fetch(url, { credentials: "include" })`) stays visible for review.
const ENV_SUFFIX_RE = new RegExp(`\\b([A-Z][A-Z0-9_]*_(?:PAT|DSN|APIKEY|CREDENTIALS?)["']?\\s*[:=]\\s*)${VALUE}`, "g");
// Compound secret names (incl. camelCase `apiKey`/`accessToken`/`clientSecret` and
// dotted paths like `auth.api-key.value`) the whole-token rule can't match. `["']?`
// covers a quoted JSON key.
// (connection_string is handled by its own full-value redactor above, not here, so
// its semicolon-delimited tail isn't truncated.)
const COMPOUND_NAMES =
  "api[_-]?key|access[_-]?(?:key|token)|client[_-]?secret|private[_-]?key|auth[_-]?token|service[_-]?role";
// Leading/trailing name spans are bounded ({0,64}) so a long identifier-like run that
// never reaches `:`/`=` (e.g. repeated `api-key` text in a minified file) can't make
// the match super-linear and stall the outbound review.
const COMPOUND_NAME_RE = new RegExp(
  `\\b([A-Za-z0-9._-]{0,64}(?:${COMPOUND_NAMES})[A-Za-z0-9._-]{0,64}["']?\\s*[:=]\\s*)${VALUE}`,
  "gi"
);

// Bare primitive/builtin TS types — a compound-name value that is one of these is a
// type annotation (`apiKey: string`), not a secret, so it's kept for the reviewer.
const PRIMITIVE_TYPE_RE =
  /^(?:string|number|boolean|bigint|symbol|object|unknown|any|never|void|null|undefined|true|false|this)$/;

/**
 * Decide whether a captured assignment value is a secret literal to mask (true) or
 * benign code to leave for the reviewer (false). `name` is the matched key name;
 * `style` is "env" (.env/config — an unquoted value IS the secret) or "compound" (a
 * code-identifier name — a member/call expression or a bare primitive type is code;
 * any other token-shaped value is a secret).
 */
function shouldRedactValue(value, name, style) {
  const v = value.trim();
  if (/^["']/.test(v)) return true; // quoted string literal
  if (v.startsWith("{")) {
    const inner = v.slice(1, -1).trim();
    if (inner.length === 0) return false;
    // A quoted literal inside the braces, or a base64/opaque token (carrying `/`, `=`,
    // or `~`), is a secret value regardless of the field name.
    if (/^["']/.test(inner) || /[/=~]/.test(inner)) return true;
    // A React `key` prop's value is a JS expression (`item.id`, `foo+bar`, `fn(x)`).
    // Case-SENSITIVE lowercase only: the React prop is `key`, whereas uppercase `KEY`
    // is an env-style secret name whose brace value must still be masked.
    if (name === "key") return false;
    // A compound code-name keeps only a clear member/call/index expression
    // (`apiKey={cfg.key}`); a bare token (`service_role={sk_live_secret}`) is masked.
    if (style === "compound") return !/[.([]/.test(inner);
    // For an env-style secret keyword (TOKEN/PASSWORD/SECRET/...), a brace value is the
    // secret itself — a passphrase, a dotted token, or any other opaque value.
    return true;
  }
  if (style === "compound") {
    if (!/^\S+$/.test(v)) return false; // a multi-token expression (`a + b`) is code
    if (/[.([<]/.test(v)) return false; // member access / call / generic / index is code
    if (PRIMITIVE_TYPE_RE.test(v)) return false; // a bare primitive type is code
    return true; // a bare token (`abc123secret`, `plain-secret`) is a literal secret
  }
  return true; // env-style: an unquoted value is the secret
}

/**
 * Run one assignment regex over `text`, masking each value that shouldRedactValue()
 * classifies as a secret (per `style`) while keeping the name + separator prefix.
 * Already-redacted placeholder values are left as-is; `bump` counts each redaction.
 */
function redactAssignments(text, re, bump, style) {
  return text.replace(re, (match, prefix, value) => {
    const residue = value.replace(/\[redacted[^\]]*\]?/g, "").replace(/["'\s]/g, "");
    if (residue === "") return match; // already a placeholder — don't re-wrap
    const name = prefix.replace(/["']?\s*[:=]\s*$/, "").replace(/^["']/, "").trim();
    if (!shouldRedactValue(value, name, style)) return match;
    bump("secret-assignment");
    return `${prefix}[redacted:secret]`;
  });
}

/** Luhn check so a random 13–19 digit run isn't redacted as a credit-card number. */
function luhnValid(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/**
 * Mask Luhn-valid 13–19 digit runs (optionally space/dash grouped) as credit cards,
 * counting each via `bump`. Non-Luhn digit runs are left untouched.
 */
function redactCreditCards(text, bump) {
  // A single bounded character class (no nested quantifier ⇒ no ReDoS, and nothing for
  // safe-regex to flag) finds candidate digit/separator runs; the digit-count + Luhn
  // check below is the real filter, so an over-broad candidate is simply rejected.
  return text.replace(/\b\d[\d -]{11,35}\d\b/g, (match) => {
    const digits = match.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19 || !luhnValid(digits)) return match;
    bump("credit-card");
    return "[redacted:credit-card]";
  });
}

// ============================================================================
// BROAD layer — redactSensitiveText only (tool output; the runner's prior
// behavior, where over-redaction is acceptable and missing a secret is not).
// Substring keyword matching with dots, ALL-CAPS env, and any-length Bearer.
// ============================================================================
const INAPP_VALUE = `(?:"[^"]{4,2000}"|'[^']{4,2000}'|[^\\s"']{4,})`;
const INAPP_KEYWORDS =
  "secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|service[_-]?role|connection[_-]?string|client[_-]?secret";
const INAPP_ENV_SUFFIX = "KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|APIKEY|PAT|DSN";
const INAPP_REDACTORS = [
  // Any-length Bearer credential (opaque; short ones can be real). Same token
  // character set as the precise redactor so `Bearer abc+def/ghi==` is fully masked.
  { re: /\bBearer\s+[A-Za-z0-9._~+/-]+={0,2}/gi, repl: "[redacted]" },
  // key=value where the key name contains a secret-ish word anywhere (dots allowed).
  { re: new RegExp(`[A-Za-z0-9._-]{0,64}(?:${INAPP_KEYWORDS})[A-Za-z0-9._-]{0,64}\\s*[:=]\\s*${INAPP_VALUE}`, "gi"), repl: "[redacted]" },
  // ALL-CAPS env var ending in a secret-ish suffix (SUPABASE_ANON_KEY, GITHUB_PAT).
  { re: new RegExp(`\\b[A-Z][A-Z0-9_]{0,60}_(?:${INAPP_ENV_SUFFIX})\\b\\s*[:=]\\s*${INAPP_VALUE}`, "g"), repl: "[redacted]" },
];

/**
 * Scrub an outbound REVIEW PROMPT. Pure: returns the safe text, per-type counts,
 * and a block decision. BLOCKS (safe = "") on a private-key marker. Precise — does
 * not over-redact ordinary code.
 */
function scrubPrompt(text) {
  if (typeof text !== "string") {
    throw new TypeError("scrubPrompt expects a string");
  }
  if (PEM_BLOCK_RE.test(text)) {
    return {
      safe: "",
      redactions: [{ type: "private-key", count: 1 }],
      blocked: true,
      blockReason: "a private key was detected in the review context",
    };
  }
  const counts = new Map();
  const bump = (type, n = 1) => counts.set(type, (counts.get(type) ?? 0) + n);
  let safe = applyRedactors(text, PROVIDER_REDACTORS, bump);
  safe = applyRedactors(safe, CLI_REDACTORS, bump);
  safe = redactAssignments(safe, ASSIGNMENT_RE, bump, "env");
  safe = redactAssignments(safe, ENV_SUFFIX_RE, bump, "env");
  safe = redactAssignments(safe, COMPOUND_NAME_RE, bump, "compound");
  safe = redactCreditCards(safe, bump);
  const redactions = [...counts.entries()].map(([type, count]) => ({ type, count }));
  return { safe, redactions, blocked: false, blockReason: null };
}

/** Total redactions across all types — handy for one-line console summaries. */
function totalRedactions(redactions) {
  return redactions.reduce((n, r) => n + r.count, 0);
}

/**
 * Redact-only scrub for TOOL OUTPUT / display (runner stdout/stderr/stdin). Runs:
 *   - the shared provider-key shapes,
 *   - the high-confidence credential/PII redactors (Basic, Cookie, email, SSN, home
 *     path, credit card) so those don't leak into the runner log/UI, and
 *   - the runner's broad keyword/any-length-Bearer net.
 * Never blanks the whole input. Emits the plain `[redacted]` marker the runner has
 * always used. (The whole-token assignment passes are intentionally skipped here —
 * the broad INAPP keyword net already covers, and over-covers, those.)
 */
function redactSensitiveText(value) {
  const noop = () => {};
  let out = applyRedactors(String(value), PROVIDER_REDACTORS, noop);
  out = applyRedactors(out, CLI_REDACTORS, noop);
  out = redactCreditCards(out, noop);
  out = applyRedactors(out, INAPP_REDACTORS, noop);
  return out.replace(/\[redacted:[^\]]*\]/g, "[redacted]");
}

/**
 * True when a private-key marker is present and the content must never be sent.
 */
function containsUnsendableSecret(value) {
  return PEM_BLOCK_RE.test(String(value));
}

module.exports = {
  scrubPrompt,
  totalRedactions,
  redactSensitiveText,
  containsUnsendableSecret,
};
