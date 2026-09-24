/**
 * Local Static Engine — regex/pattern detection over diff hunks (FR-8).
 *
 * Phase 1 scaffold: the public surface is fixed here so the rest of the codebase
 * can compile against it, but the rule set itself lands in Phase 2.
 */

import type { LocalFinding } from './types';

export type { LocalFinding } from './types';

/**
 * Runs the configured rule set over a unified diff.
 *
 * @param diff Raw output of `git diff --cached` (unified diff format).
 * @returns One finding per matched rule per line, in file/line order.
 */
export async function runLocalScan(_diff: string): Promise<LocalFinding[]> {
  throw new Error('runLocalScan: Local rule engine is not implemented yet (Phase 2).');
}
