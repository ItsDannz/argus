/**
 * Process exit codes, defined once.
 *
 * These are a public interface: the pre-commit hook passes them straight to
 * Git, and any script wrapping CodeGuard will branch on them. They are
 * therefore deliberately distinct rather than "0 or non-zero", because the
 * difference between "scanned clean", "found something and refused", and "the
 * tool could not run" is exactly the difference a caller needs to report
 * honestly.
 *
 *   OK                scanned, nothing at or above the block threshold
 *   ERROR             CodeGuard itself could not run (not a repo, unreadable
 *                     input, a bug)
 *   NOT_IMPLEMENTED   the command exists but is not built yet
 *   BLOCKED           the scan completed and found a blocking issue (FR-9).
 *                     Git treats every non-zero code as "refuse the commit",
 *                     so this blocks exactly like ERROR does — the distinction
 *                     exists so the user, and our own tests, can tell why.
 */

export const EXIT = {
  OK: 0,
  ERROR: 1,
  NOT_IMPLEMENTED: 2,
  BLOCKED: 3,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];
