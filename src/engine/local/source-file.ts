/**
 * Facts about the source file a diff line belongs to.
 *
 * Two concerns live here because both are "what kind of file is this?" questions
 * answered from the file extension alone, with no parsing:
 *
 *   1. Which rule set applies (`fileExtension` feeding `rulesForFile`).
 *   2. Which lines are whole-line comments and can be skipped entirely.
 *
 * ─── Why comment awareness matters ──────────────────────────────────────────
 * A regex cannot tell code from a comment, so a comment reading
 * "we removed the call to strcpy() here" would be reported as a vulnerability.
 * That kind of false positive is corrosive out of all proportion to its
 * frequency: it makes the tool look wrong in exactly the demo where it needs to
 * look trustworthy.
 *
 * ─── Scope, and what is deliberately NOT handled ────────────────────────────
 * Only WHOLE-LINE comments are skipped — a line whose first non-whitespace
 * characters are a comment marker, and which therefore cannot contain code.
 * That guarantee is what makes the skip safe: it can never hide executable code.
 *
 * Still unhandled, by explicit decision, because each needs real parsing:
 *   - block comments (`/* ... *\/`) and their continuation lines
 *   - trailing comments on a line that also contains code
 * A line containing `strcpy(a, b); // was strcpy(c, d)` is still flagged once.
 */

/**
 * Line-comment prefixes by file extension.
 *
 * The C-family entries list ONLY `//`. That omission is the whole point of making
 * this file-type aware: in C and C++, `#` is a preprocessor directive, not a
 * comment, so `#define COPY(d, s) strcpy(d, s)` is executable code and must not
 * be skipped. In Python or Shell the same leading `#` really is a comment.
 *
 * A file extension that is absent from this map gets NO prefix, which means no
 * skipping. That is the conservative default: never silently ignore a line we are
 * not certain is a comment, because a skipped line is a vulnerability we would
 * never report.
 */
const LINE_COMMENT_PREFIXES: Readonly<Record<string, readonly string[]>> = {
  // C-family and friends: "//" only, never "#".
  '.c': ['//'],
  '.h': ['//'],
  '.cc': ['//'],
  '.cpp': ['//'],
  '.cxx': ['//'],
  '.hpp': ['//'],
  '.hh': ['//'],
  '.hxx': ['//'],
  '.ino': ['//'],
  '.java': ['//'],
  '.cs': ['//'],
  '.go': ['//'],
  '.rs': ['//'],
  '.swift': ['//'],
  '.kt': ['//'],
  '.kts': ['//'],
  '.scala': ['//'],
  '.dart': ['//'],
  '.groovy': ['//'],

  // JavaScript / TypeScript.
  '.js': ['//'],
  '.jsx': ['//'],
  '.mjs': ['//'],
  '.cjs': ['//'],
  '.ts': ['//'],
  '.tsx': ['//'],
  '.mts': ['//'],
  '.cts': ['//'],

  // PHP accepts both.
  '.php': ['//', '#'],

  // Hash-comment languages, where "#" genuinely is a comment.
  '.py': ['#'],
  '.pyi': ['#'],
  '.rb': ['#'],
  '.sh': ['#'],
  '.bash': ['#'],
  '.zsh': ['#'],
  '.pl': ['#'],
  '.r': ['#'],
  '.yml': ['#'],
  '.yaml': ['#'],
  '.toml': ['#'],
  '.ps1': ['#'],
};

/**
 * Returns the lower-cased extension of a path, including the dot.
 * Returns '' when the path has no extension (e.g. `Makefile`, `Dockerfile`).
 */
export function fileExtension(filePath: string): string {
  const slash = Math.max(filePath.lastIndexOf('/'), filePath.lastIndexOf('\\'));
  const dot = filePath.lastIndexOf('.');
  // A dot before the last slash belongs to a directory name, not the file.
  if (dot === -1 || dot < slash) return '';
  return filePath.slice(dot).toLowerCase();
}

/** The line-comment prefixes for a path. Empty array means "do not skip anything". */
export function commentPrefixesFor(filePath: string): readonly string[] {
  return LINE_COMMENT_PREFIXES[fileExtension(filePath)] ?? [];
}

/**
 * Returns true when a line is entirely a comment, and so cannot contain code.
 *
 * The test is per-LINE and syntax-based, which has a known gap: Markdown has no
 * entry in LINE_COMMENT_PREFIXES, so a vulnerable-looking example inside a fenced
 * code block is scanned as though it were live code. That is why a file whose
 * examples ARE the hazardous patterns has to be excluded by path — see the
 * `excludePaths` list in this repository's own `.codeguardrc.json`, which covers
 * `rules.ts`, the fixtures, the tests, the prompts and these docs.
 *
 * Teaching this function about fenced blocks, and more generally about telling a
 * quoted example from live code, is a deliberate future improvement rather than an
 * oversight: it changes what the rule engine considers code, so it wants its own
 * evidence and tests instead of riding along with a documentation change.
 *
 * @param filePath Path from the diff, used only to pick the comment syntax.
 * @param line     A single line of source, with the diff marker already removed.
 */
export function isWholeLineComment(filePath: string, line: string): boolean {
  const prefixes = commentPrefixesFor(filePath);
  if (prefixes.length === 0) return false;

  const trimmed = line.trim();
  if (trimmed === '') return false;

  return prefixes.some((prefix) => trimmed.startsWith(prefix));
}
