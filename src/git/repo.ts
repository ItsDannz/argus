/**
 * Git access, via `simple-git` as PRD §9.1 specifies (FR-1).
 *
 * Everything git-specific lives here so that neither the scan engine nor the
 * hook installer has to know how to talk to a repository. That also keeps the
 * engine unit-testable against plain diff strings with no repo on disk.
 */

import path from 'node:path';

import { simpleGit, type SimpleGit } from 'simple-git';

/**
 * Arguments for the staged diff (FR-1: staged changes are the analysis unit).
 *
 * Each flag is doing work, and most of them defend the diff parser:
 *
 *   --cached         staged changes only, which is what a pre-commit hook sees
 *   --no-color       a user with `color.ui = always` would otherwise get ANSI
 *                    escapes embedded in the diff, which the parser would read
 *                    as part of the line content and silently corrupt matching
 *   --no-ext-diff    ignore any external diff driver configured in the repo,
 *                    whose output would not be a unified diff at all
 *   --no-textconv    ignore textconv filters, which rewrite content before diffing
 *   --src-prefix / --dst-prefix   pin the prefixes to a/ and b/. Without these,
 *                    `diff.mnemonicPrefix = true` yields i/ w/ c/ o/ instead, and
 *                    the parser's "strip a/ or b/" step would stop working
 *   -U3              three lines of context, which the patch stage will want
 */
const STAGED_DIFF_ARGS = [
  'diff',
  '--cached',
  '--no-color',
  '--no-ext-diff',
  '--no-textconv',
  '--src-prefix=a/',
  '--dst-prefix=b/',
  '-U3',
] as const;

/** A configured simple-git client rooted at `repoRoot`. */
export function gitAt(repoRoot: string): SimpleGit {
  return simpleGit(repoRoot);
}

/**
 * Finds the repository root containing `cwd`.
 *
 * Returns null rather than throwing when there is no repository, because "this
 * is not a Git repository" is a normal answer for a CLI, not an error.
 */
export async function findRepoRoot(cwd: string): Promise<string | null> {
  try {
    const output = await simpleGit(cwd).raw(['rev-parse', '--show-toplevel']);
    const root = output.trim();
    return root === '' ? null : root;
  } catch {
    return null;
  }
}

/**
 * Returns the staged diff, or an empty string when nothing is staged.
 *
 * Uses `raw()` rather than simple-git's `diff()` helper: the helper parses the
 * diff into its own object graph, and this project already has a parser that
 * produces the hunk/line-number model the engine needs. Going through the raw
 * text keeps a single source of truth for diff shapes.
 */
export async function getStagedDiff(repoRoot: string): Promise<string> {
  return simpleGit(repoRoot).raw([...STAGED_DIFF_ARGS]);
}

export type HookMechanism = 'husky' | 'native';

export interface HookLocation {
  mechanism: HookMechanism;
  /** Absolute path of the pre-commit hook file to write. */
  hookPath: string;
  /** Raw `core.hooksPath` value, or null when unset. Surfaced for reporting. */
  coreHooksPath: string | null;
}

/**
 * True when a `core.hooksPath` value points at Husky's directory.
 *
 * Husky v9 sets `core.hooksPath=.husky/_`, and `.husky/_/pre-commit` is a
 * generated shim that sources the user-editable `.husky/pre-commit`. Writing to
 * the shim would be undone the next time Husky runs, so a Husky repo has to be
 * written to `.husky/pre-commit` instead. Older Husky versions and hand-written
 * setups point straight at `.husky`, so both shapes are accepted.
 */
function isHuskyHooksPath(hooksPath: string): boolean {
  const normalised = hooksPath.replace(/\\/g, '/').replace(/\/+$/, '');
  return /(^|\/)\.husky(\/_)?$/.test(normalised);
}

/**
 * Decides where the pre-commit hook belongs, and by which mechanism.
 *
 * The rule is "write where Git will actually look". `git rev-parse --git-path`
 * is what answers that, since it already takes `core.hooksPath` and linked
 * worktrees into account — so a repo using a custom hooks directory is honoured
 * rather than having a hook written somewhere Git ignores. Husky is the one
 * case that needs special handling, for the shim reason above.
 *
 * Note that a `.husky/` directory which exists but is NOT active (no
 * `core.hooksPath`) is correctly ignored: Git would not run a hook there.
 */
export async function locatePreCommitHook(repoRoot: string): Promise<HookLocation> {
  const git = simpleGit(repoRoot);

  // `--default ''` keeps this exit-0 when the key is unset. A bare
  // `git config --get` exits 1, which simple-git turns into a thrown error, and
  // "unset" is a normal state rather than a failure.
  const coreHooksPath = (await git.raw(['config', '--get', '--default', '', 'core.hooksPath'])).trim();

  if (coreHooksPath !== '' && isHuskyHooksPath(coreHooksPath)) {
    return {
      mechanism: 'husky',
      hookPath: path.join(repoRoot, '.husky', 'pre-commit'),
      coreHooksPath,
    };
  }

  const reported = (await git.raw(['rev-parse', '--git-path', 'hooks/pre-commit'])).trim();
  return {
    mechanism: 'native',
    // --git-path returns a path relative to the repo root when it can, so it has
    // to be resolved before being written to.
    hookPath: path.isAbsolute(reported) ? reported : path.resolve(repoRoot, reported),
    coreHooksPath: coreHooksPath === '' ? null : coreHooksPath,
  };
}
