/**
 * Git pre-commit hook integration (FR-2, FR-9, PRD §10.1).
 *
 * Three responsibilities, kept together because they are one feature:
 *
 *   scanDiff()               — the check itself: diff in, findings + exit code out
 *   runPreCommitCheck()      — the hook body: capture the staged diff, then scanDiff
 *   installPreCommitHook()   — the installer: write the hook that calls the body
 *
 * ─── The failure policy, which is the one thing to understand here ───────────
 * The hook blocks for exactly one reason: a finding at or above the configured
 * block threshold. Every other failure — CodeGuard cannot be found, the config
 * is malformed, an unexpected exception — prints a loud warning on stderr and
 * ALLOWS the commit.
 *
 * That is not laziness, it is the whole reason the check survives. PRD §3 lists
 * "avoid blocking developer flow" as a goal, §8 requires failures to degrade
 * gracefully rather than blocking the commit process, and §11 accepts that a
 * frustrated developer will reach for `--no-verify` and says not to fight it. A
 * tool that blocks commits on its own bugs gets bypassed permanently within a
 * day, and a bypassed hook protects nothing. A tool that shouts and passes gets
 * its bug reported and fixed. See ALLOW_COMMIT_ON_INTERNAL_ERROR.
 */

import { access, chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
  loadConfig,
  type CodeGuardConfig,
  type ConfigProblem,
} from '../config/load';
import { cloneConfig, DEFAULT_CONFIG } from '../config/schema';
import type { LocalFinding } from '../engine/local/types';
import { runLocalScan } from '../engine/local';
import { decideMode, loadEnvironment, type Environment } from '../engine/mode';
import { redactApiKey } from '../engine/remote/redact';
import { runRemoteScan, type DeepAnalysis, type LlmClient } from '../engine/remote';
import { evaluateThreshold, type ThresholdDecision } from '../engine/threshold';
import { EXIT } from '../exit-codes';
import { findRepoRoot, getStagedDiff, locatePreCommitHook, type HookMechanism } from '../git/repo';
import {
  renderConfigProblems,
  renderFindingsReport,
  renderNotes,
  renderRemoteExtras,
  renderVerdict,
  type EngineName,
  type RenderOptions,
} from '../report/render';

/**
 * Marks a hook file as ours, so a re-install updates in place instead of
 * treating it as somebody else's hook. Versioned so a future incompatible
 * rewrite can recognise an older script.
 */
export const HOOK_MARKER = 'codeguard:pre-commit-hook v1';

/** Suffix used when an existing hook is moved aside rather than overwritten. */
export const BACKUP_SUFFIX = '.codeguard-backup';

/**
 * Whether an unexpected internal error allows the commit.
 *
 * True, for the reasons in the file header. Flipping this to false makes
 * CodeGuard fail closed: safer in principle, but a single bug then blocks every
 * commit in the repository until it is fixed. The warning path is loud and
 * repeats on every commit precisely so that failing open is not silent.
 */
const ALLOW_COMMIT_ON_INTERNAL_ERROR = true;

export interface ScanResult {
  exitCode: number;
  findings: LocalFinding[];
  decision: ThresholdDecision;
  config: CodeGuardConfig;
  configPath: string | null;
  configProblems: ConfigProblem[];
  /** Which engine actually produced `findings` — not which one was requested. */
  engine: EngineName;
  /** Operational notes: exclusions, redactions, truncation, fallbacks. */
  notes: string[];
  /** Remote only: findings deep analysis cleared as false positives. */
  dismissed: LocalFinding[];
  /** Remote only: per-hunk deep analysis, including any suggested patch. */
  analyses: DeepAnalysis[];
}

export interface ScanIo {
  /** Where findings go. Defaults to stdout — this is the product's output. */
  write?: (text: string) => void;
  /** Where warnings go. Defaults to stderr, so piped stdout stays parseable. */
  writeError?: (text: string) => void;
  useColor?: boolean;
}

export interface ScanDiffOptions extends ScanIo {
  diff: string;
  repoRoot: string;
  /** Force the rule-based engine. */
  local?: boolean;
  /** Force the AI engine. An error if no key is available, never a fallback. */
  remote?: boolean;
  /**
   * Overrides the detected environment.
   *
   * The seam that makes remote-mode behaviour testable without a network, an
   * API key, or a scratch checkout containing a `.env`. Production never passes
   * this; the environment is read from the repository being committed to.
   */
  environment?: Environment;
  /**
   * Overrides the AI provider. Stubbed in tests so a scan under test never
   * reaches the network — and so a failure can be induced on demand, which is
   * the only way to exercise the fallback deterministically.
   */
  client?: LlmClient;
}

function resolveIo(io: ScanIo): { write: (text: string) => void; writeError: (text: string) => void; render: RenderOptions } {
  return {
    write: io.write ?? ((text: string) => void process.stdout.write(text)),
    writeError: io.writeError ?? ((text: string) => void process.stderr.write(text)),
    render: { useColor: io.useColor === true },
  };
}

/**
 * Scans one diff and reports it.
 *
 * Split from {@link runPreCommitCheck} so it can be driven with a diff from
 * anywhere — a file, stdin, a fixture — with no repository involved. That is
 * what makes the whole reporting and threshold path testable without shelling
 * out to Git.
 *
 * ─── Mode selection, and the one fallback that exists ────────────────────────
 * `decideMode` chooses the engine (FR-3). There are exactly two ways Remote Mode
 * ends up not being used:
 *
 *   - `--remote` with no key. An ERROR, not a fallback. The developer asked for
 *     an AI scan; quietly giving them a regex scan while the flag implied
 *     otherwise is a lie about what ran.
 *   - A keyless default, or a configured key that fails at runtime. A fallback,
 *     with a loud warning, because the alternative is blocking a commit over a
 *     network blip (PRD §6.3, §8).
 *
 * Falling back from a FAILED remote call keeps the run alive but must never look
 * like a successful remote scan, so the warning says plainly that the AI check
 * did not run and the header names the local engine.
 *
 * Never throws, and never blocks on anything except a real finding.
 */
export async function scanDiff(options: ScanDiffOptions): Promise<ScanResult> {
  const { write, writeError, render } = resolveIo(options);
  const loaded = await loadConfig(options.repoRoot);

  const configWarning = renderConfigProblems(loaded.problems, loaded.path, render);
  if (configWarning !== '') writeError(`${configWarning}\n\n`);

  const environment = options.environment ?? (await loadEnvironment(options.repoRoot));
  const mode = decideMode({
    ...(options.local === undefined ? {} : { local: options.local }),
    ...(options.remote === undefined ? {} : { remote: options.remote }),
    environment,
    ...(loaded.config.model === undefined ? {} : { configModel: loaded.config.model }),
  });

  if (mode.kind === 'error') {
    // A request CodeGuard cannot honour. Exit ERROR, not BLOCKED: nothing was
    // found, so reporting a security block would be false.
    writeError(`CodeGuard: ${mode.message}\n`);
    return {
      exitCode: EXIT.ERROR,
      findings: [],
      decision: evaluateThreshold([], loaded.config.threshold),
      config: loaded.config,
      configPath: loaded.path,
      configProblems: loaded.problems,
      engine: 'local',
      notes: [mode.message],
      dismissed: [],
      analyses: [],
    };
  }

  const notes: string[] = [];

  if (mode.kind === 'remote') {
    try {
      const outcome = await runRemoteScan({
        diff: options.diff,
        credentials: mode.credentials,
        remote: loaded.config.remote,
        exclude: loaded.isExcluded,
        // Progress goes to stderr: stdout is the report, and a report with
        // status lines mixed into it is not parseable.
        onProgress: (message) => writeError(`${message}\n`),
        ...(options.client === undefined ? {} : { client: options.client }),
      });

      const decision = evaluateThreshold(outcome.findings, loaded.config.threshold);
      const remoteRender: RenderOptions = { ...render, engine: 'remote' };

      write(`${renderFindingsReport(outcome.findings, remoteRender)}\n`);
      const extras = renderRemoteExtras(outcome, render);
      if (extras !== '') write(`\n${extras}\n`);
      if (outcome.findings.length > 0) {
        const { blockOn, warnOn } = loaded.config.threshold;
        write(`\n${renderVerdict(decision, blockOn, warnOn, render)}\n`);
      }

      const noteBlock = renderNotes(outcome.notes, render);
      if (noteBlock !== '') writeError(`${noteBlock}\n`);

      return {
        exitCode: decision.blocking.length > 0 ? EXIT.BLOCKED : EXIT.OK,
        findings: outcome.findings,
        decision,
        config: loaded.config,
        configPath: loaded.path,
        configProblems: loaded.problems,
        engine: 'remote',
        notes: outcome.notes,
        dismissed: outcome.dismissed,
        analyses: outcome.analyses,
      };
    } catch (error) {
      // Redacted here as well as inside the client. The client already strips
      // the key from its own messages, but this is the last point before an
      // arbitrary provider string reaches the terminal, and FR-10 is the one
      // requirement in this project where a single component getting it wrong is
      // irreversible — the key would be in the user's scrollback and their CI
      // log. Two independent guards is the right number for that.
      const message = redactApiKey(
        error instanceof Error ? error.message : String(error),
        mode.credentials.apiKey,
      );
      writeError(
        [
          '[CODEGUARD] Remote AI Mode failed, so the AI check DID NOT RUN.',
          `  ${message}`,
          '  Falling back to the local rule engine. The results below come from regex rules only —',
          '  a clean scan here does not mean the AI pass found nothing.',
          '',
        ].join('\n'),
      );
      notes.push(`Remote AI Mode failed and CodeGuard fell back to Local Mode: ${message}`);
    }
  }

  const findings = await runLocalScan(options.diff, { exclude: loaded.isExcluded });
  const decision = evaluateThreshold(findings, loaded.config.threshold);

  write(`${renderFindingsReport(findings, render)}\n`);
  if (findings.length > 0) {
    const { blockOn, warnOn } = loaded.config.threshold;
    write(`\n${renderVerdict(decision, blockOn, warnOn, render)}\n`);
  }

  return {
    exitCode: decision.blocking.length > 0 ? EXIT.BLOCKED : EXIT.OK,
    findings,
    decision,
    config: loaded.config,
    configPath: loaded.path,
    configProblems: loaded.problems,
    engine: 'local',
    notes,
    dismissed: [],
    analyses: [],
  };
}

export interface PreCommitOptions extends ScanIo {
  /** Directory the hook was invoked from. Defaults to the process cwd. */
  cwd?: string;
  /** Force Local Mode. */
  local?: boolean;
  /** Force Remote Mode (an error, not a fallback, without a key). */
  remote?: boolean;
}

/**
 * The hook body. Captures the staged diff (FR-1) and scans it.
 *
 * Git invokes hooks with the working directory set to the repository root, so
 * the default cwd is correct in production; `cwd` exists so tests can point it
 * at a scratch repository.
 *
 * @returns The exit code the caller must propagate. Git refuses the commit for
 *          any non-zero value.
 */
export async function runPreCommitCheck(options: PreCommitOptions = {}): Promise<ScanResult> {
  const { write, writeError, render } = resolveIo(options);
  const cwd = options.cwd ?? process.cwd();

  /**
   * A result for a scan that produced no findings.
   *
   * Deliberately separate from {@link internalError}, which PRINTS. Building the
   * empty-diff result by calling it meant `git commit --amend` with nothing
   * staged — and `git commit --allow-empty` — printed "the security check did
   * not run because of an internal error ... please report this" for a
   * completely normal action. Found by dogfooding this repo's own hook; the
   * lesson is that a helper with a printing side effect is not a constructor.
   */
  const emptyResult = (exitCode: number): ScanResult => ({
    exitCode,
    findings: [],
    decision: evaluateThreshold([], DEFAULT_CONFIG.threshold),
    config: cloneConfig(DEFAULT_CONFIG),
    configPath: null,
    configProblems: [],
    engine: 'local',
    notes: [],
    dismissed: [],
    analyses: [],
  });

  const internalError = (error: unknown): ScanResult => {
    const message = error instanceof Error ? error.message : String(error);
    writeError(
      [
        'CodeGuard: the security check did not run because of an internal error.',
        `  ${message}`,
        ALLOW_COMMIT_ON_INTERNAL_ERROR
          ? '  The commit has been ALLOWED so your work is not blocked, but no scan happened.'
          : '  The commit has been BLOCKED. Re-run with `git commit --no-verify` to bypass.',
        '  Please report this: https://github.com/codeguard/codeguard/issues',
        '',
      ].join('\n'),
    );
    return emptyResult(ALLOW_COMMIT_ON_INTERNAL_ERROR ? EXIT.OK : EXIT.ERROR);
  };

  try {
    const repoRoot = await findRepoRoot(cwd);
    if (repoRoot === null) {
      writeError('CodeGuard: not inside a Git repository — nothing to scan.\n');
      return emptyResult(EXIT.ERROR);
    }

    const diff = await getStagedDiff(repoRoot);
    // `git commit --allow-empty`, or `git commit --amend` with nothing staged,
    // produces nothing to analyse. Not an error, and not a warning either.
    if (diff.trim() === '') {
      write('CodeGuard: no staged changes to scan.\n');
      return emptyResult(EXIT.OK);
    }

    return await scanDiff({ ...options, diff, repoRoot });
  } catch (error) {
    return internalError(error);
  }
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

export interface HookScriptInput {
  /**
   * Repo-relative POSIX path of a preserved previous hook, or null when the
   * install did not displace one.
   */
  previousHookRelativePath: string | null;
  mechanism: HookMechanism;
}

/**
 * Builds the hook script text.
 *
 * A pure function so the generated shell can be asserted on directly — the
 * script is the part of this feature most likely to break silently, and a test
 * that reads its text back is far cheaper than discovering it in a real commit.
 *
 * Built as an array of lines rather than a template literal: the script is full
 * of `${VAR}` shell expansions, every one of which would otherwise need
 * escaping against TypeScript interpolation.
 */
export function buildHookScript(input: HookScriptInput): string {
  const lines: string[] = [
    '#!/usr/bin/env sh',
    `# ${HOOK_MARKER}`,
    '#',
    '# Installed by `codeguard install`, which is safe to re-run.',
    '#',
    '# Runs `codeguard scan --staged` against the staged diff and refuses the',
    '# commit when a finding is at or above the configured block threshold (FR-9).',
    '#',
    '# This hook fails OPEN and shouts: it refuses a commit only for a real finding.',
    '# Anything else — the CLI missing, a broken config, an internal error — warns on',
    '# stderr and allows the commit. A gate that blocks on its own bugs gets bypassed',
    '# permanently with --no-verify, and then protects nothing.',
    '#',
    '# Environment:',
    '#   CODEGUARD_BIN   executable to run, when codeguard is neither on PATH nor',
    '#                   installed under ./node_modules/.bin',
    '#',
    '# Escape hatch: git commit --no-verify',
    '',
  ];

  if (input.previousHookRelativePath !== null) {
    lines.push(
      '# --- preserved previous hook -------------------------------------------',
      '# A pre-commit hook already existed here. It is preserved intact and still',
      '# runs FIRST, so an existing lint-staged or test hook keeps working exactly as',
      '# it did before. If it fails, the commit stops, as it always did.',
      `CODEGUARD_PREVIOUS="${input.previousHookRelativePath}"`,
      'if [ -f "$CODEGUARD_PREVIOUS" ]; then',
      '  if [ -x "$CODEGUARD_PREVIOUS" ]; then',
      '    "$CODEGUARD_PREVIOUS" "$@" || exit $?',
      '  else',
      '    # Not executable (common on Windows, where Git runs hooks regardless of',
      '    # the mode bit). Fall back to sh so the preserved hook still runs.',
      '    sh "$CODEGUARD_PREVIOUS" "$@" || exit $?',
      '  fi',
      'fi',
      '',
    );
  }

  lines.push(
    '# --- codeguard ----------------------------------------------------------',
    '# Git runs hooks with the working directory at the repository root, so the',
    '# relative paths below resolve correctly.',
    'CODEGUARD="${CODEGUARD_BIN:-}"',
    'if [ -z "$CODEGUARD" ]; then',
    '  if [ -x "./node_modules/.bin/codeguard" ]; then',
    '    CODEGUARD="./node_modules/.bin/codeguard"',
    '  else',
    '    CODEGUARD="codeguard"',
    '  fi',
    'fi',
    '',
    'if [ ! -x "$CODEGUARD" ] && ! command -v "$CODEGUARD" >/dev/null 2>&1; then',
    '  echo "CodeGuard: executable not found (tried CODEGUARD_BIN, ./node_modules/.bin/codeguard, and codeguard on PATH)." >&2',
    '  echo "CodeGuard: the commit is ALLOWED, but NO security check ran." >&2',
    '  echo "CodeGuard: install it, or set CODEGUARD_BIN to its path." >&2',
    '  exit 0',
    'fi',
    '',
    'exec "$CODEGUARD" scan --staged',
    '',
  );

  return lines.join('\n');
}

export interface InstallResult {
  mechanism: HookMechanism;
  /** Absolute path of the hook file that was written. */
  hookPath: string;
  /** What happened to whatever was there before. */
  action: 'created' | 'updated' | 'wrapped';
  /** Absolute path of a preserved previous hook, when one was moved aside. */
  backupPath: string | null;
  /** Raw `core.hooksPath`, for reporting which mechanism was detected and why. */
  coreHooksPath: string | null;
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

/** Never clobber an earlier backup — a preserved hook may itself be the original. */
async function uniqueBackupPath(hookPath: string): Promise<string> {
  const base = `${hookPath}${BACKUP_SUFFIX}`;
  if (!(await exists(base))) return base;
  for (let n = 2; ; n++) {
    const candidate = `${base}.${n}`;
    if (!(await exists(candidate))) return candidate;
  }
}

/**
 * A path the hook script can use, relative to the repository root where the
 * hook runs. Falls back to an absolute POSIX path if the target is somehow
 * outside the repository, since a `../..` chain would be fragile.
 */
function scriptPath(repoRoot: string, target: string): string {
  const relative = path.relative(repoRoot, target);
  const usable = relative !== '' && !relative.startsWith('..') ? relative : target;
  // Forward slashes only: backslashes are escape characters in sh.
  return usable.split(path.sep).join('/');
}

/**
 * Installs the pre-commit hook (FR-2).
 *
 * Three behaviours that matter, all of them about not surprising the user:
 *
 *   1. An existing hook is never silently destroyed. If it is not ours, it is
 *      moved to `<hook>.codeguard-backup` and the script we write calls it
 *      first, so a lint-staged or test hook keeps running. Appending instead
 *      would be simpler but wrong: a preserved hook ending in `exit 0` would
 *      make anything appended after it dead code.
 *   2. Re-running is idempotent. Our marker is checked before writing, so a
 *      second install updates in place rather than nesting a second call.
 *   3. The chosen mechanism is reported, so `codeguard install` says which of
 *      the two paths it took instead of leaving the user to go looking.
 *
 * @param repoRoot Absolute path to the repository root.
 */
export async function installPreCommitHook(repoRoot: string): Promise<InstallResult> {
  const location = await locatePreCommitHook(repoRoot);
  const { hookPath } = location;

  let existing: string | null = null;
  try {
    existing = await readFile(hookPath, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  let action: InstallResult['action'];
  let backupPath: string | null = null;

  if (existing === null) {
    action = 'created';
  } else if (existing.includes(HOOK_MARKER)) {
    // Ours. Overwrite in place — this is what makes a re-run idempotent.
    action = 'updated';
  } else {
    action = 'wrapped';
    backupPath = await uniqueBackupPath(hookPath);
    await rename(hookPath, backupPath);
  }

  // A preserved hook from an earlier install must survive a re-install. Without
  // this, the second run would rewrite the script with no reference to the
  // backup and the user's original hook would stop running — silently.
  if (action !== 'wrapped') {
    const knownBackup = `${hookPath}${BACKUP_SUFFIX}`;
    if (await exists(knownBackup)) backupPath = knownBackup;
  }

  const script = buildHookScript({
    previousHookRelativePath: backupPath === null ? null : scriptPath(repoRoot, backupPath),
    mechanism: location.mechanism,
  });

  await mkdir(path.dirname(hookPath), { recursive: true });
  await writeFile(hookPath, script, 'utf8');

  // POSIX needs the executable bit or Git will not run the hook. Windows has no
  // such bit and Git for Windows runs hooks regardless, so this is skipped
  // there rather than making a meaningless syscall.
  if (process.platform !== 'win32') await chmod(hookPath, 0o755);

  return {
    mechanism: location.mechanism,
    hookPath,
    action,
    backupPath,
    coreHooksPath: location.coreHooksPath,
  };
}

export type { ConfigProblem };
