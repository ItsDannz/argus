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
import { fileExtension } from './source-file';

/** File extensions treated as C/C++ for the C-specific detectors. */
const C_FAMILY = ['.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx', '.ino'];

/** Languages with an `eval`-style dynamic-code-execution primitive. */
const SCRIPT_LANGUAGES = [
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.mts',
  '.cts',
  '.py',
  '.pyi',
  '.php',
  '.rb',
  '.lua',
  '.pl',
];

/** Languages where `new Function(...)` compiles code at runtime. */
const JS_LANGUAGES = ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts'];

const PYTHON = ['.py', '.pyi'];

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

// ---------------------------------------------------------------------------
// Dynamic code execution
// ---------------------------------------------------------------------------

const DYNAMIC_CODE_RULES: Rule[] = [
  {
    id: 'dynamic-code-execution-eval',
    category: 'other',
    severity: 'High',
    message:
      'eval() parses and runs its argument as code. If any part of that string can be influenced by a user, it is arbitrary code execution. Prefer an explicit parser (JSON.parse, ast.literal_eval) or a lookup table of allowed operations.',
    pattern: /\beval\s*\(/,
    // Case-sensitive on purpose: `Eval(` is far more likely to be somebody's own
    // function than the built-in.
    appliesTo: SCRIPT_LANGUAGES,
  },
  {
    id: 'dynamic-code-execution-function-constructor',
    category: 'other',
    severity: 'High',
    message:
      'The Function constructor compiles its argument as code and is equivalent to eval() — it is not a safer alternative. Prefer an explicit parser or a lookup table.',
    pattern: /\bnew\s+Function\s*\(/,
    appliesTo: JS_LANGUAGES,
  },
  {
    id: 'dynamic-code-execution-python-exec',
    category: 'other',
    severity: 'High',
    message:
      'exec() compiles and runs arbitrary Python. On any input a user can influence this is arbitrary code execution. Use ast.literal_eval for data, or a dispatch table for behaviour.',
    pattern: /\bexec\s*\(/,
    appliesTo: PYTHON,
  },
];

// ---------------------------------------------------------------------------
// Insecure cryptography
// ---------------------------------------------------------------------------

/**
 * Severity note: MD5 and SHA-1 are Medium rather than High because the same call
 * is entirely legitimate for a non-security checksum (content hashing, ETags,
 * cache keys). Flagging those as High would be exactly the noise PRD §11 warns
 * about. DES and ECB get High, because neither has a legitimate modern use once
 * you have decided to encrypt something at all.
 */
const CRYPTO_RULES: Rule[] = [
  {
    id: 'insecure-crypto-md5',
    category: 'insecure_crypto',
    severity: 'Medium',
    message:
      'MD5 is cryptographically broken — collisions are practical to construct. It is acceptable for non-security checksums, but never for passwords, signatures, or any integrity check an attacker could influence. Use SHA-256 or better.',
    // Covers both call forms (hashlib.md5(...), md5(...)) and the string form
    // passed to a crypto API (createHash('md5'), MessageDigest.getInstance("MD5")).
    pattern: /\bmd5\s*\(|['"]md5['"]/i,
  },
  {
    id: 'insecure-crypto-sha1',
    category: 'insecure_crypto',
    severity: 'Medium',
    message:
      'SHA-1 is cryptographically broken for collision resistance (SHAttered). Fine for non-security checksums, never for signatures or password storage. Use SHA-256 or better.',
    pattern: /\bsha1\s*\(|['"]sha1['"]/i,
  },
  {
    id: 'insecure-crypto-des',
    category: 'insecure_crypto',
    severity: 'High',
    message:
      'DES and 3DES are obsolete: DES has a 56-bit key that is brute-forceable, and 3DES is deprecated by NIST. Use AES-256.',
    // Covers the direct call (DES(...)), the PyCrypto/Java constructor form
    // (DES.new(...), DESCipher(...)), the TripleDES spelling, and the string
    // form (createCipheriv('des-ede3-cbc', ...)). The \b anchors keep
    // identifiers like hash_codes( from matching.
    pattern: /\bTripleDES(?:\.new)?\s*\(|\bDES(?:Cipher)?(?:\.new)?\s*\(|['"]des(?:['"]|-)/i,
  },
  {
    id: 'insecure-crypto-ecb',
    category: 'insecure_crypto',
    severity: 'High',
    message:
      'ECB mode encrypts every block independently, so identical plaintext blocks produce identical ciphertext and the structure of the data leaks. Use AES-GCM, or CBC with a random IV.',
    // `MODE_ECB` needs its own alternative: the underscore before "ECB" is a word
    // character, so \bECB\b does not match inside it.
    pattern: /MODE_ECB|\bECB\b/i,
  },
];

/**
 * The built-in rule set, in report order (secrets, C, injection, SQL, dynamic
 * code, crypto). Ordering is presentation-only — `runLocalScan` groups by line,
 * not by rule, so reordering here does not change results.
 */
export const DEFAULT_RULES: readonly Rule[] = [
  ...SECRET_RULES,
  ...UNSAFE_C_RULES,
  ...COMMAND_INJECTION_RULES,
  ...SQL_RULES,
  ...DYNAMIC_CODE_RULES,
  ...CRYPTO_RULES,
];

/**
 * Selects the rules that apply to a given path, by file extension.
 *
 * @param rules      Candidate rules (defaults to the built-in set).
 * @param filePath   Path as it appears in the diff.
 */
export function rulesForFile(rules: readonly Rule[], filePath: string): Rule[] {
  const ext = fileExtension(filePath);
  return rules.filter((rule) => rule.appliesTo === undefined || rule.appliesTo.includes(ext));
}
