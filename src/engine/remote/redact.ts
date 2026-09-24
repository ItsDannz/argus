/**
 * Redaction pass for Remote Mode (PRD §9.3, NFR §8).
 *
 * "diffs sent to the API should be redacted/truncated if they contain values
 * matching secret patterns". This module is the redaction half of that, and it
 * runs on every diff before transmission — always, with no flag to turn it off,
 * because the moment it becomes optional it becomes off.
 *
 * ─── Why this is NOT the detection rule set ──────────────────────────────────
 * `engine/local/rules.ts` also matches secrets, and reusing it here would be
 * wrong. The two have opposite cost functions:
 *
 *   Detection  — a false positive blocks a commit the developer did not deserve
 *                to have blocked, so those rules are tuned for precision.
 *   Redaction  — a false negative transmits a live credential to a third party,
 *                so this is tuned for recall. Better to mangle a harmless
 *                string than to leak a real key.
 *
 * Different costs, different patterns, so they are separate lists on purpose.
 *
 * ─── Two invariants this must not break ──────────────────────────────────────
 * 1. LINE COUNT IS PRESERVED. Every replacement happens *within* a line, never
 *    across one. The model answers with `line_range`s that we match back to
 *    hunks, so shifting a line would silently point its answers at the wrong
 *    code.
 * 2. THE PLACEHOLDER IS LOUD. `«REDACTED:aws-access-key»` is not valid in any
 *    language we scan and cannot be mistaken for real code. That matters
 *    because a Stage-2 patch can legitimately quote a line we redacted, and the
 *    patch would then contain the placeholder. The pipeline checks for that
 *    explicitly (see engine/remote/index.ts), so the placeholder has to be
 *    unmistakable for the check to be worth anything.
 *
 * ─── What is deliberately NOT reported ───────────────────────────────────────
 * Redactions carry a file and a kind, never a line number. A second line counter
 * living here would be a second source of truth for the one thing diff.ts says
 * must be exactly right, and the developer already has their own staged diff to
 * look at. The value is never returned at all — FR-10's reasoning about the API
 * key applies to every other credential that lands in a diff, too.
 */

/**
 * The `g` flag is used throughout this file, which the rest of the codebase
 * forbids for `Rule.pattern`. The difference is the call: `exec()` and `test()`
 * carry `lastIndex` between calls on a shared object, so a global regex silently
 * skips every second match. `String.prototype.replace()` does not — the spec has
 * it write `lastIndex = 0` before it starts and again when it finishes. Every
 * pattern below is used with `replace()` only, and nothing here may be used with
 * `exec()` or `test()`.
 *
 * The `lookbehind`/`lookahead` pairs are load-bearing rather than decorative:
 * they match the *value* alone, so replacing it leaves the identifier that names
 * it intact. Matching the whole `apiKey = "..."` expression instead would strip
 * the model's view of what the code was doing, which is the context it needs to
 * judge whether the line is even a problem.
 */
interface RedactionPattern {
  /** Reported to the user. Describes the *kind* of secret, never its value. */
  label: string;
  pattern: RegExp;
}

/**
 * Marks text as already redacted. Used both to build the placeholder and to
 * detect one, so the two can never drift apart.
 */
const PLACEHOLDER_MARK = '«REDACTED:';

/** Nothing that looks like a credential survives into this string. */
function placeholder(label: string): string {
  return `${PLACEHOLDER_MARK}${label}»`;
}

/**
 * Whether text already carries a redaction placeholder.
 *
 * Exported because the pipeline needs it: a Stage-2 patch can legitimately quote
 * a line we redacted, and applying that patch would write a placeholder into the
 * developer's file. See engine/remote/index.ts.
 */
export function containsPlaceholder(text: string): boolean {
  return text.includes(PLACEHOLDER_MARK);
}

/**
 * Replaces a whole line's content while keeping its diff marker.
 *
 * Only needed for values with no per-line shape — a private key's base64 body
 * only means anything in aggregate. Everything else replaces a substring and
 * leaves the marker and the rest of the line alone. Dropping the leading `+`
 * would leave the model with a diff that no longer parses as one.
 */
function replaceContent(rawLine: string, replacement: string): string {
  const marker = rawLine.charAt(0);
  return marker === '+' || marker === '-' || marker === ' ' ? `${marker}${replacement}` : replacement;
}

/** `/^-----BEGIN ... PRIVATE KEY-----/` without the anchor, for scanning. */
const PRIVATE_KEY_BEGIN = /-----\s?BEGIN[^-]{0,40}PRIVATE KEY-----/;
const PRIVATE_KEY_END = /-----\s?END[^-]{0,40}PRIVATE KEY-----/;

/**
 * Identifiers whose value is a credential. Used as a lookbehind anchor.
 *
 * `api[_-]?key` also covers the bare `apikey`, so it is not listed twice.
 */
const SECRET_IDENTIFIER =
  '(?:api[_-]?key|secret|token|passwd|password|passphrase|private[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|credential)';

const REDACTION_PATTERNS: readonly RedactionPattern[] = [
  // --- Credentials with published, recognisable shapes ---------------------
  // Private keys are handled separately, above: a PEM body has no per-line
  // shape, so it cannot be matched here.
  { label: 'aws-access-key', pattern: /\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/g },
  { label: 'github-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g },
  { label: 'slack-token', pattern: /\bxox[aboprs]-[A-Za-z0-9-]{10,}\b/g },
  { label: 'openai-key', pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { label: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { label: 'stripe-key', pattern: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { label: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { label: 'npm-token', pattern: /\bnpm_[A-Za-z0-9]{30,}\b/g },

  // The userinfo component of a URL. Lookarounds keep the scheme, host and
  // surrounding syntax readable while removing the credential itself.
  { label: 'credential-in-url', pattern: /(?<=:\/\/)[^/\s:@]{1,64}:[^/\s:@]{1,128}(?=@)/g },

  // --- A quoted value assigned to a credential-naming identifier ------------
  // 12 characters is the floor: shorter values are config words ("none",
  // "changeme") that are not credentials and whose removal would only cost the
  // model context.
  {
    label: 'assigned-secret',
    pattern: new RegExp(
      `(?<=\\b${SECRET_IDENTIFIER}\\b\\s*[:=]\\s*["'\`])[^"'\`\\n]{12,}(?=["'\`])`,
      'gi',
    ),
  },
];

/**
 * Words that make a nearby opaque string worth redacting.
 *
 * The heuristic below is deliberately NOT "any long random-looking string". A
 * `package-lock.json` diff is full of sha512 integrity hashes, and redacting
 * those would gut the diff the model is supposed to reason about while
 * protecting nothing. Requiring a secret-naming word on the same line is what
 * keeps the heuristic off lockfiles, checksums and git SHAs while still catching
 * a credential whose format nobody has published.
 */
const SECRET_CONTEXT = /(?:key|token|secret|password|passwd|pwd|credential|auth|bearer)/i;

/** Quoted strings of 20+ characters, followed by their quote character. */
const QUOTED_VALUE = /(["'`])([^"'`\n]{20,})\1/g;

/**
 * Whether a string looks generated rather than typed.
 *
 * Two character classes plus a digit, not three classes: a hex secret
 * (`a3f9...`) and a lowercase base64 secret both have only two, and requiring
 * three would walk straight past them. The length floor and the same-line
 * context word are what carry the precision instead.
 */
function looksRandom(value: string): boolean {
  const hasDigit = /[0-9]/.test(value);
  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  const hasSymbol = /[^A-Za-z0-9]/.test(value);
  const classes = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);
  return hasDigit && classes >= 2;
}

/**
 * Backstop for credentials whose format is unknown: a long, generated-looking
 * quoted string on a line that also names a secret.
 *
 * Runs after the named patterns. It must not touch a value one of them already
 * took, and that check is `containsPlaceholder` rather than an assertion about
 * the value's shape — see the guard in {@link redactDiff}.
 */
function redactUnrecognised(line: string, note: (label: string) => string): string {
  if (!SECRET_CONTEXT.test(line)) return line;

  return line.replace(QUOTED_VALUE, (whole, quote: string, value: string) => {
    if (containsPlaceholder(value)) return whole;
    if (!looksRandom(value)) return whole;
    return `${quote}${note('high-entropy-value')}${quote}`;
  });
}

/** One redacted value, reported without its contents. */
export interface Redaction {
  /** Repo-relative path the value was found in, or "" before the first header. */
  file: string;
  label: string;
}

export interface RedactionResult {
  /** The diff, safe to transmit. Same number of lines as the input. */
  diff: string;
  /** What was removed, for reporting. Never contains the values themselves. */
  redactions: Redaction[];
}

/**
 * Strips secret-looking values from a diff.
 *
 * Reports only the kind of each secret and the file it was in.
 *
 * @param diff Raw output of `git diff --cached`.
 * @returns The redacted diff and a list of what was removed. The line count of
 *          `diff` always equals that of the input.
 */
export function redactDiff(diff: string): RedactionResult {
  const redactions: Redaction[] = [];
  let file = '';
  let inPrivateKey = false;

  const note = (label: string): string => {
    redactions.push({ file, label });
    return placeholder(label);
  };

  const out = diff.split('\n').map((rawLine) => {
    // Track the file so a redaction can be attributed. `+++ ` is the only line
    // that carries the new-side path in a form usable directly.
    if (rawLine.startsWith('+++ ')) {
      const named = rawLine.slice(4).trim();
      if (named !== '/dev/null') file = named.replace(/^[ab]\//, '');
      return rawLine;
    }
    // Hunk headers and file headers carry no values worth redacting, and
    // rewriting them could corrupt the structure the model relies on.
    if (rawLine.startsWith('@@') || rawLine.startsWith('diff --git')) return rawLine;

    // A PEM body is base64 that means nothing line by line, so it is tracked
    // as a block. One redaction is recorded, on the BEGIN line, rather than one
    // per line of a 30-line key.
    if (inPrivateKey) {
      if (PRIVATE_KEY_END.test(rawLine)) inPrivateKey = false;
      return replaceContent(rawLine, placeholder('private-key'));
    }
    if (PRIVATE_KEY_BEGIN.test(rawLine)) {
      inPrivateKey = true;
      return replaceContent(rawLine, note('private-key'));
    }

    let line = rawLine;
    for (const { label, pattern } of REDACTION_PATTERNS) {
      line = line.replace(pattern, (match: string) => {
        // The guard that keeps labels honest. Patterns run most-specific first,
        // but they overlap: a GitHub token is also a value assigned to an
        // identifier called `token`. Without this, the generic pattern matched
        // second and rewrote the specific label — and the entropy backstop
        // rewrote it again. First recogniser wins, and its label is the one the
        // user sees.
        if (containsPlaceholder(match)) return match;
        return note(label);
      });
    }

    return redactUnrecognised(line, note);
  });

  return { diff: out.join('\n'), redactions };
}

/**
 * Removes a known secret from arbitrary text before it is shown or logged.
 *
 * Exists for one narrow but important case: an HTTP client's error message can
 * echo the request that failed, and that request carries the key in a header.
 * FR-10 says the key is never logged, and "the client would not do that" is not
 * a guarantee worth betting a credential on.
 *
 * @param apiKey The live key, or null. Blank input returns the text unchanged so
 *               callers need not special-case a missing key.
 */
export function redactApiKey(text: string, apiKey: string | null): string {
  if (apiKey === null || apiKey === '') return text;
  return text.split(apiKey).join(placeholder('api-key'));
}
