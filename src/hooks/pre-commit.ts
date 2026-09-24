/**
 * Git pre-commit hook integration (FR-2, FR-9, PRD §10.1).
 *
 * Two separate responsibilities, deliberately kept in one module:
 *
 *   runPreCommitCheck()      — the *hook body*. Runs when `git commit` fires,
 *                              reads the staged diff, scans it, and decides
 *                              whether to block the commit.
 *   installPreCommitHook()   — the *installer*. Writes the hook script into
 *                              .husky/ (or .git/hooks/) so the body above runs.
 *
 * Phase 1 scaffold only — both are implemented in Phase 3.
 */

/**
 * Entry point invoked by the installed hook. Must set a non-zero exit code to
 * block the commit; a clean run lets the commit proceed.
 */
export async function runPreCommitCheck(): Promise<void> {
  throw new Error('runPreCommitCheck: pre-commit hook is not implemented yet (Phase 3).');
}

/**
 * Idempotently installs the pre-commit hook into the given repository.
 *
 * @param repoRoot Absolute path to the repository root.
 */
export async function installPreCommitHook(_repoRoot: string): Promise<void> {
  throw new Error('installPreCommitHook: hook installation is not implemented yet (Phase 3).');
}
