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

/**
 * Stages files into the index (FR-7: an applied patch is staged for the user).
 *
 * Applying a patch edits the working tree, and the pre-commit gate reads the
 * INDEX. Without this step an applied fix would be invisible to the re-scan
 * that follows it, and the developer would be shown the same blocking verdict
 * next to a file that no longer contains the vulnerability.
 *
 * Only the paths it is given: `git add -A` would sweep up whatever else the
 * developer had in flight, and a security tool silently staging unrelated work
 * is a worse outcome than the minor inconvenience it saves.
 */
export async function stageFiles(repoRoot: string, files: readonly string[]): Promise<void> {
  if (files.length === 0) return;
  await gitAt(repoRoot).add([...files]);
}

export type HookMechanism = 'husky' | 'native';

export interface HookLocation {
  mechanism: HookMechanism;
  /** Absolute path of the pre-commit hook file to write. */
  hookPath: string;
  /** Raw `core.hooksPath` value, when it is set to something usable. Null otherwise. */
  coreHooksPath: string | null;
  /**
   * True when `core.hooksPath` is set to the empty string.
   *
   * Kept separate from a null `coreHooksPath` because the two are not the same
   * situation for the user. An absent key is ordinary; the empty value makes Git
   * run NO hook at any path, so an install into that repository is dormant and
   * the command has to say so rather than report a bare success.
   */
  hooksPathIsEmpty: boolean;
}

/**
 * Absolute `$GIT_COMMON_DIR`, which `--git-common-dir` may report relatively.
 *
 * The common dir rather than the per-worktree one, because that is where Git
 * keeps hooks: in a linked worktree `--git-dir` is `.git/worktrees/<name>`, and
 * a hook written there would never run.
 */
async function gitCommonDir(git: SimpleGit, repoRoot: string): Promise<string> {
  const reported = (await git.raw(['rev-parse', '--git-common-dir'])).trim();
  return path.isAbsolute(reported) ? reported : path.resolve(repoRoot, reported);
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
 *
 * A `core.hooksPath` set to the empty string is treated as unset. That is not
 * cosmetic: `git rev-parse --git-path` HONOURS the empty value and answers
 * `/pre-commit`, i.e. the filesystem root. Resolving that put the hook at
 * `C:\pre-commit` on Windows and `/pre-commit` on POSIX, and the installer's
 * `mkdir` then failed with EPERM trying to create the root directory. The value
 * is also a known way to try to switch hooks off, so writing anything under it
 * is the last thing to want.
 *
 * The case is reported as its own field rather than folded into a null
 * `coreHooksPath` so a caller can warn about it: the hook is written, and Git
 * runs nothing, which is a success message and an unprotected repository at the
 * same time.
 */
export async function locatePreCommitHook(repoRoot: string): Promise<HookLocation> {
  const git = simpleGit(repoRoot);

  // Whether the key is SET is read here, not just its value, and that distinction
  // is load-bearing: an empty value needs a warning an absent key must not get.
  // `--get` cannot make it — git answers an absent key and an empty one with `""`
  // and `"\n"` respectively, which trim to the same string, and simple-git does
  // not throw on the exit code that separates them (measured: it resolves both to
  // ""). `--get-regexp` prints a line whenever the key is set, empty value
  // included, and prints nothing when it is absent, so the difference is in the
  // output rather than in a status code nobody surfaces.
  let coreHooksPath: string | null = null;
  let hooksPathIsEmpty = false;
  const configured = (await git.raw(['config', '--get-regexp', '^core\\.hooksPath$'])).trim();
  if (configured !== '') {
    const separator = configured.indexOf(' ');
    // No separator means the key is set with nothing after it: the empty string.
    const value = separator === -1 ? '' : configured.slice(separator + 1).trim();
    if (value === '') hooksPathIsEmpty = true;
    else coreHooksPath = value;
  }

  if (coreHooksPath !== null && isHuskyHooksPath(coreHooksPath)) {
    return {
      mechanism: 'husky',
      hookPath: path.join(repoRoot, '.husky', 'pre-commit'),
      coreHooksPath,
      hooksPathIsEmpty: false,
    };
  }

  // `--git-path` answers "where will Git look", which is exactly the question,
  // except in the empty-value case above where it answers with the root. Going
  // through the common dir for that one case asks the same question of a setting
  // `core.hooksPath` cannot influence.
  const reported = hooksPathIsEmpty
    ? path.join(await gitCommonDir(git, repoRoot), 'hooks', 'pre-commit')
    : (await git.raw(['rev-parse', '--git-path', 'hooks/pre-commit'])).trim();

  return {
    mechanism: 'native',
    // Both branches can report a path relative to the repo root, so it has to be
    // resolved before being written to.
    hookPath: path.isAbsolute(reported) ? reported : path.resolve(repoRoot, reported),
    coreHooksPath,
    hooksPathIsEmpty,
  };
}
