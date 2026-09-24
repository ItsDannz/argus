#!/usr/bin/env node
/**
 * CodeGuard CLI entry point.
 *
 * Commands:
 *   scan      analyse a diff and report findings (staged changes by default).
 *             This is what the pre-commit hook runs.
 *   install   write the pre-commit hook (Husky if the repo uses it, else .git/hooks)
 *   patch     re-open the interactive apply flow from the last saved report (Phase 5)
 *   config    show, or initialise, .codeguardrc.json
 *
 * Exit codes are the CLI's contract with the hook and with any script wrapping
 * it — see exit-codes.ts. They are distinct on purpose: an unimplemented
 * command must never be mistakable for a clean scan, and "found a blocking
 * issue" must never be mistakable for "the tool crashed".
 */

import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { Command } from 'commander';

import { CONFIG_FILENAME, cloneConfig, DEFAULT_CONFIG } from './config/schema';
import { loadConfig } from './config/load';
import { decideMode, loadEnvironment } from './engine/mode';
import { EXIT } from './exit-codes';
import { findRepoRoot } from './git/repo';
import { installPreCommitHook, runPreCommitCheck, scanDiff } from './hooks/pre-commit';
import { renderConfigProblems } from './report/render';

const VERSION = '0.1.0';

/**
 * Reports that a command exists but has no implementation yet.
 *
 * Writes to stderr (not stdout) so machine-readable stdout stays clean, and
 * exits 2 — distinct from 0 ("scanned, nothing found"), 1 ("tool errored") and
 * 3 ("found a blocking issue"), so a stub can never impersonate a clean scan.
 */
function notImplemented(command: string, phase: number): void {
  process.stderr.write(`codeguard ${command}: not implemented yet — scheduled for Phase ${phase}.\n`);
  process.exitCode = EXIT.NOT_IMPLEMENTED;
}

/**
 * Whether ANSI colour is appropriate.
 *
 * Default off when stdout is not a terminal, so redirecting to a file or piping
 * into another tool never produces escape sequences. `NO_COLOR` is honoured
 * because it is the established convention for opting out.
 */
function colorEnabled(colorOption: boolean | undefined): boolean {
  if (colorOption === false) return false;
  const noColor = process.env['NO_COLOR'];
  if (noColor !== undefined && noColor !== '') return false;
  return process.stdout.isTTY === true;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

async function resolveRepoRoot(cwd: string): Promise<string> {
  return (await findRepoRoot(cwd)) ?? cwd;
}

/**
 * Repo-relative path with forward slashes, for display.
 *
 * Git speaks POSIX paths everywhere else (diff headers, hook paths), so showing
 * the user a Windows-style `.git\hooks\pre-commit` next to them would read as a
 * different path rather than the same one.
 */
function displayPath(repoRoot: string, target: string): string {
  const relative = path.relative(repoRoot, target);
  return (relative === '' ? target : relative).split(path.sep).join('/');
}

const program = new Command();

program
  .name('codeguard')
  .description(
    'Autonomous Code Security Guard & Patch Agent — scans staged Git changes for security and logic issues before they enter history.',
  )
  .version(VERSION);

program
  .command('scan')
  .description('Scan a diff for security and logic issues (staged changes by default)')
  .option('--staged', 'scan the Git index (default)')
  .option('--diff <file>', "scan a diff from a file instead of the index ('-' for stdin)")
  .option('--local', 'force Local Static Engine Mode (rule-based, no API key needed)')
  .option('--remote', 'force Remote AI Mode (requires DEEPSEEK_API_KEY)')
  .option('--no-color', 'disable colour in output')
  .action(async (options: { diff?: string; local?: boolean; remote?: boolean; color?: boolean }) => {
    const useColor = colorEnabled(options.color);
    const mode = {
      ...(options.local === undefined ? {} : { local: options.local }),
      ...(options.remote === undefined ? {} : { remote: options.remote }),
    };

    if (options.diff !== undefined) {
      const diff = options.diff === '-' ? await readStdin() : await readFile(options.diff, 'utf8');
      const result = await scanDiff({
        diff,
        repoRoot: await resolveRepoRoot(process.cwd()),
        useColor,
        ...mode,
      });
      process.exitCode = result.exitCode;
      return;
    }

    const result = await runPreCommitCheck({ useColor, ...mode });
    process.exitCode = result.exitCode;
  });

program
  .command('install')
  .description('Install the pre-commit hook (Husky if the repo uses it, otherwise .git/hooks)')
  .action(async () => {
    const cwd = process.cwd();
    const repoRoot = await findRepoRoot(cwd);
    if (repoRoot === null) {
      process.stderr.write('codeguard install: not inside a Git repository.\n');
      process.exitCode = EXIT.ERROR;
      return;
    }

    const result = await installPreCommitHook(repoRoot);
    const shown = displayPath(repoRoot, result.hookPath);

    // Which mechanism was chosen is stated rather than left implicit: the user
    // asked for a hook and deserves to know where it went and why.
    const via = result.mechanism === 'husky' ? 'Husky' : 'native Git hooks';
    process.stdout.write(`CodeGuard: installed pre-commit hook via ${via} (${shown})\n`);

    if (result.mechanism === 'husky' && result.coreHooksPath !== null) {
      process.stdout.write(`  detected via core.hooksPath = ${result.coreHooksPath}\n`);
    }

    if (result.action === 'wrapped' && result.backupPath !== null) {
      const backup = displayPath(repoRoot, result.backupPath);
      process.stdout.write(
        `  an existing hook was preserved at ${backup} and will still run first — nothing was overwritten\n`,
      );
    } else if (result.action === 'updated') {
      process.stdout.write('  updated the existing CodeGuard hook in place (re-install is safe)\n');
    }

    process.stdout.write('  the hook runs: codeguard scan --staged\n');
    process.stdout.write('  escape hatch:  git commit --no-verify\n');
  });

program
  .command('patch')
  .description('Reopen the interactive patch/apply flow for findings you skipped earlier')
  .option('--from-report', 'reuse findings from .codeguard/report.json instead of rescanning')
  .action(() => notImplemented('patch', 5));

program
  .command('config')
  .description(`Show, validate, or initialise CodeGuard configuration (${CONFIG_FILENAME})`)
  .option('--init', `write a starter ${CONFIG_FILENAME} with the defaults`)
  .option('--validate', `check ${CONFIG_FILENAME} and exit non-zero when it is malformed`)
  .action(async (options: { init?: boolean; validate?: boolean }) => {
    const repoRoot = await resolveRepoRoot(process.cwd());

    /**
     * Proactive check, so a typo is found here rather than mid-commit. The
     * pre-commit hook deliberately does NOT block on a broken config (see the
     * failure policy in hooks/pre-commit.ts), which makes a way to ask "is my
     * config actually being read?" worth having.
     *
     * Exit 1 rather than 3: a malformed config is an operational problem, not a
     * security finding, and conflating the two would let a CI job treat a typo
     * as a vulnerability.
     */
    if (options.validate === true) {
      const checked = await loadConfig(repoRoot);
      if (checked.problems.length === 0) {
        process.stdout.write(
          checked.path === null
            ? `CodeGuard: no ${CONFIG_FILENAME} found — running on built-in defaults.\n`
            : `CodeGuard: ${displayPath(repoRoot, checked.path)} is valid.\n`,
        );
        return;
      }
      process.stderr.write(
        `${renderConfigProblems(checked.problems, checked.path, { useColor: colorEnabled(undefined) })}\n`,
      );
      process.exitCode = EXIT.ERROR;
      return;
    }

    if (options.init === true) {
      const target = path.join(repoRoot, CONFIG_FILENAME);
      try {
        await writeFile(target, `${JSON.stringify(cloneConfig(DEFAULT_CONFIG), null, 2)}\n`, {
          encoding: 'utf8',
          flag: 'wx', // fail if it exists, rather than discarding a real config
        });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
          process.stderr.write(
            `codeguard config: ${CONFIG_FILENAME} already exists — not overwriting it.\n`,
          );
          process.exitCode = EXIT.ERROR;
          return;
        }
        throw error;
      }
      process.stdout.write(`CodeGuard: wrote ${displayPath(repoRoot, target)}\n`);
      return;
    }

    const loaded = await loadConfig(repoRoot);
    const environment = await loadEnvironment(repoRoot);
    const mode = decideMode({
      environment,
      ...(loaded.config.model === undefined ? {} : { configModel: loaded.config.model }),
    });

    // The mode is reported rather than left to be inferred from whether an API
    // key happens to be exported. "Why did my commit just make a network call?"
    // is a question this line answers before it is asked.
    const modeLine =
      mode.kind === 'remote'
        ? `remote AI (${mode.credentials.model})`
        : mode.kind === 'local'
          ? 'local rule engine'
          : 'error — see below';

    const lines = [
      'CodeGuard configuration',
      `  config file    ${loaded.path ?? 'none — using defaults'}`,
      `  block on       ${loaded.config.threshold.blockOn}`,
      `  warn on        ${loaded.config.threshold.warnOn}`,
      `  exclude paths  ${loaded.config.excludePaths.length > 0 ? loaded.config.excludePaths.join(', ') : 'none'}`,
      `  model          ${loaded.config.model ?? 'the built-in default'}`,
      `  mode           ${modeLine}`,
      `  deep hunks     up to ${loaded.config.remote.maxDeepAnalysisHunks} per scan`,
    ];
    process.stdout.write(`${lines.join('\n')}\n`);

    if (mode.kind === 'error') {
      process.stderr.write(`\nCodeGuard: ${mode.message}\n`);
      process.exitCode = EXIT.ERROR;
    }

    const warning = renderConfigProblems(loaded.problems, loaded.path, { useColor: colorEnabled(undefined) });
    if (warning !== '') process.stderr.write(`\n${warning}\n`);
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`codeguard: ${message}\n`);
  process.exitCode = EXIT.ERROR;
});
