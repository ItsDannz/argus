/**
 * The Local Static Engine's built-in rule set (FR-8, PRD §6.2).
 *
 * Each detector is a DATA ENTRY in an array rather than hardcoded logic. That is
 * deliberate: FR-13 (user-defined regex rules) was cut from the MVP, but because
 * rules are values, adding it later means appending to this array rather than
 * rewriting the scanner. `runLocalScan` accepts a `rules` override for exactly
 * that reason.
 *
 * ─── The false-positive discipline ──────────────────────────────────────────
 * PRD §11 names false positives eroding trust as a top risk, and a pre-commit
 * hook is the worst possible place for them: a noisy gate gets disabled with
 * `--no-verify` and then protects nobody. So rules here are deliberately
 * conservative. Where a pattern alone over-triggers — a password assigned the
 * placeholder "changeme", a genuine parameterised query — the rule supplies a
 * `refine` predicate to suppress the match. Missing a marginal finding is the
 * preferred failure mode.
 *
 * ─── Known limitation ───────────────────────────────────────────────────────
 * These are regexes over single lines, so they cannot tell code from comments or
 * string literals. A comment mentioning `strcpy(` will be flagged. That is
 * inherent to the Local Mode design (PRD §6.2: "pattern-based warnings only — no
 * contextual reasoning") and is precisely the gap Remote Mode exists to fill.
 */

import type { Category, Severity } from '../../prompts/security-agent-prompts';

/** File extensions treated as C/C++ for the C-specific detectors. */
const C_FAMILY = ['.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx', '.ino'];

export interface Rule {
  /** Stable identifier. Used for config overrides (FR-9) and suppressions. */
  id: string;
  category: Category;
  severity: Severity;
  /** Human-readable explanation, doubling as the remediation note (PRD §6.2). */
  message: string;
  /**
   * Detection pattern, tested against a single line of added code.
   *
   * Must NOT use the `g` flag. A global regex carries `lastIndex` state between
   * `.exec()` calls, so reusing one across lines would skip every second match.
   */
  pattern: RegExp;
  /** Restricts the rule to certain file extensions. Omitted = applies to all files. */
  appliesTo?: readonly string[];
  /**
   * Optional second-stage filter, called only after `pattern` matches. Return
   * false to suppress a false positive. Receives the exec array so it can
   * inspect capture groups.
   */
  refine?: (line: string, match: RegExpExecArray) => boolean;
}

// ---------------------------------------------------------------------------
// Hardcoded secrets
// ---------------------------------------------------------------------------

/**
 * Values that look like a credential but are placeholders, documentation, or
 * masks. Flagging these is the single biggest source of secret-scanner noise.
 */
const PLACEHOLDER_VALUES = new Set([
  'changeme',
  'change_me',
  'change-me',
  'placeholder',
  'example',
  'password',
  'passwd',
  'secret',
  'test',
  'dummy',
  'todo',
  'fixme',
  'your_password',
  'your-password',
  'your_api_key',
  'your-api-key',
  'redacted',
  'none',
  'null',
  'undefined',
]);

/** Returns true when a matched secret value is obviously not a real credential. */
function looksLikePlaceholder(value: string): boolean {
  const v = value.trim().toLowerCase();
  if (v === '') return true;
  if (PLACEHOLDER_VALUES.has(v)) return true;
  // Masks: "xxxxx", "*****", "....."
  if (/^(?:x{3,}|\*{3,}|\.{3,})$/.test(v)) return true;
  // Documentation slots: <YOUR_API_KEY>
  if (/^<.*>$/.test(v)) return true;
  // Interpolation that survived as literal text: ${KEY}
  if (/^\$\{.*\}$/.test(v)) return true;
  // Printf-style placeholders: %s, %d
  if (/^%[a-z]$/.test(v)) return true;
  return false;
}

const SECRET_RULES: Rule[] = [
  {
    id: 'hardcoded-secret-assignment',
    category: 'hardcoded_secret',
    severity: 'High',
    message:
      'Possible hardcoded credential. Load it from an environment variable or a secrets manager and rotate the value if it was ever real (FR-10).',
    pattern:
      /(?:api[_-]?key|secret|password|passwd|pwd|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*[:=]\s*(['"])([^'"]*)\1/i,
    refine: (_line, match) => {
      const value = match[2] ?? '';
      if (looksLikePlaceholder(value)) return false;
      // Very short "secrets" are far more often flags, column names, or test
      // sentinels than real credentials.
      return value.length >= 6;
    },
  },
  {
    id: 'hardcoded-secret-aws-key',
    category: 'hardcoded_secret',
    severity: 'Critical',
    message:
      'Hardcoded AWS access key ID. Rotate this key immediately with your provider — it must be treated as compromised the moment it is committed.',
    // AKIA = long-lived IAM key, ASIA = temporary STS credential.
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  },
  {
    id: 'hardcoded-secret-private-key',
    category: 'hardcoded_secret',
    severity: 'Critical',
    message:
      'Private key material committed to source control. Remove the file, rotate the key pair, and purge it from Git history.',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
  },
];

// ---------------------------------------------------------------------------
// Unsafe C functions
// ---------------------------------------------------------------------------

const UNSAFE_C_RULES: Rule[] = [
  {
    id: 'unsafe-c-gets',
    category: 'unsafe_c_function',
    severity: 'Critical',
    message:
      'gets() cannot be used safely: it performs no bounds check and was removed from the C11 standard. Use fgets() instead.',
    pattern: /\bgets\s*\(/,
    appliesTo: C_FAMILY,
  },
  {
    id: 'unsafe-c-strcpy',
    category: 'unsafe_c_function',
    severity: 'High',
    message:
      'strcpy() copies without bounding the destination and is a classic buffer overflow source. Use strncpy_s()/strlcpy() with an explicit size, or std::string.',
    pattern: /\bstrcpy\s*\(/,
    appliesTo: C_FAMILY,
  },
  {
    id: 'unsafe-c-sprintf',
    category: 'unsafe_c_function',
    severity: 'High',
    message:
      'sprintf() does not bound its output and can overflow the buffer. Use snprintf() with the destination size.',
    pattern: /\bsprintf\s*\(/,
    appliesTo: C_FAMILY,
  },
];

// ---------------------------------------------------------------------------
// Command injection
// ---------------------------------------------------------------------------

const COMMAND_INJECTION_RULES: Rule[] = [
  {
    id: 'command-injection-system',
    category: 'command_injection',
    severity: 'Critical',
    message:
      'system() runs its argument through a shell, so any attacker-influenced part of the command becomes arbitrary command execution. Use an exec-family call with an argument vector instead (execve, CreateProcess, os.execv).',
    pattern: /\bsystem\s*\(/,
    // Not restricted to C: the same call shape exists in Python (os.system),
    // PHP, and Ruby, and is dangerous in all of them. The `\b` anchor keeps
    // `MySystem(` and `.system_utils(` from matching.
  },
];

// ---------------------------------------------------------------------------
// Raw / concatenated SQL
// ---------------------------------------------------------------------------

/** SQL verbs whose presence marks a string as a query rather than prose. */
const SQL_VERB = String.raw`(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO|DROP\s+(?:TABLE|DATABASE)|ALTER\s+TABLE|TRUNCATE\s+TABLE|UNION\s+SELECT|CREATE\s+TABLE)`;

const SQL_REMEDIATION =
  'Use a parameterised query / prepared statement so user input is bound as a parameter and can never be parsed as SQL.';

const SQL_RULES: Rule[] = [
  {
    id: 'sql-string-concatenation',
    category: 'sql_injection',
    severity: 'Critical',
    message: `SQL assembled with string concatenation. ${SQL_REMEDIATION}`,
    // A quoted string containing a SQL verb, immediately followed by "+".
    pattern: new RegExp(String.raw`(['"])[^'"]*\b${SQL_VERB}\b[^'"]*\1\s*\+`, 'i'),
  },
  {
    id: 'sql-template-interpolation',
    category: 'sql_injection',
    severity: 'Critical',
    message: `SQL built by JavaScript template interpolation. ${SQL_REMEDIATION}`,
    // A template literal containing a SQL verb and a ${...} substitution.
    pattern: new RegExp(String.raw`\`[^\`]*\b${SQL_VERB}\b[^\`]*\$\{`, 'i'),
  },
  {
    id: 'sql-fstring-interpolation',
    category: 'sql_injection',
    severity: 'Critical',
    message: `SQL built by Python f-string interpolation. ${SQL_REMEDIATION}`,
    pattern: new RegExp(String.raw`\bf['"][^'"]*\b${SQL_VERB}\b[^'"]*\{`, 'i'),
  },
  {
    id: 'sql-percent-format',
    category: 'sql_injection',
    severity: 'Critical',
    message: `SQL built with Python %-formatting. ${SQL_REMEDIATION}`,
    // "SELECT ... %s" % value   |   "SELECT ... %(name)s" % params
    pattern: new RegExp(String.raw`(['"])[^'"]*\b${SQL_VERB}\b[^'"]*\1\s*%\s*(?:\(|[A-Za-z_])`, 'i'),
  },
  {
    id: 'sql-str-format',
    category: 'sql_injection',
    severity: 'Critical',
    message: `SQL built with str.format(). ${SQL_REMEDIATION}`,
    pattern: new RegExp(String.raw`(['"])[^'"]*\b${SQL_VERB}\b[^'"]*\1\s*\.\s*format\s*\(`, 'i'),
  },
];

/**
 * The built-in rule set, in report order (secrets, then C, then injection, then
 * SQL). Ordering is presentation-only — `runLocalScan` groups by line, not by
 * rule, so reordering here does not change results.
 */
export const DEFAULT_RULES: readonly Rule[] = [
  ...SECRET_RULES,
  ...UNSAFE_C_RULES,
  ...COMMAND_INJECTION_RULES,
  ...SQL_RULES,
];

/**
 * Selects the rules that apply to a given path, by file extension.
 *
 * @param rules      Candidate rules (defaults to the built-in set).
 * @param filePath   Path as it appears in the diff.
 */
export function rulesForFile(rules: readonly Rule[], filePath: string): Rule[] {
  const dot = filePath.lastIndexOf('.');
  const ext = dot === -1 ? '' : filePath.slice(dot).toLowerCase();
  return rules.filter((rule) => rule.appliesTo === undefined || rule.appliesTo.includes(ext));
}
