#!/usr/bin/env node
/**
 * CodeGuard CLI entry point.
 *
 * Command surface is fixed to the three commands the PRD specifies (§5.1):
 *   scan    — analyse the staged diff and report findings
 *   patch   — re-open the interactive apply flow from the last saved report
 *   config  — inspect/initialise .codeguardrc.json
 *
 * Phase 1 scaffold: every command is wired into commander and `--help` lists
 * them, but the handlers are stubs. A stub exits with code 2 rather than 0 so an
 * unimplemented scan can never be mistaken for a clean scan by a caller (such as
 * the pre-commit hook in Phase 3).
 */

import { Command } from 'commander';

const VERSION = '0.1.0';

/**
 * Reports that a command exists but has no implementation yet.
 *
 * Writes to stderr (not stdout) so that machine-readable stdout stays clean, and
 * sets exit code 2 — distinct from 0 ("scanned, nothing found") and 1
 * ("tool errored"), which callers will need to tell apart in Phase 3.
 */
function notImplemented(command: string, phase: number): void {
  process.stderr.write(
    `codeguard ${command}: not implemented yet — scheduled for Phase ${phase}.\n`,
  );
  process.exitCode = 2;
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
  .description('Scan the staged diff (git diff --cached) for security and logic issues')
  .option('--local', 'force Local Static Engine Mode (rule-based, no API key needed)')
  .option('--remote', 'force Remote AI Mode (requires DEEPSEEK_API_KEY)')
  .action(() => notImplemented('scan', 2));

program
  .command('patch')
  .description('Reopen the interactive patch/apply flow for findings you skipped earlier')
  .option('--from-report', 'reuse findings from .codeguard/report.json instead of rescanning')
  .action(() => notImplemented('patch', 5));

program
  .command('config')
  .description('Show or initialise CodeGuard configuration (.codeguardrc.json)')
  .action(() => notImplemented('config', 2));

program.parseAsync(process.argv).catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`codeguard: ${message}\n`);
  process.exitCode = 1;
});
