/**
 * The published CLI, run as a child process.
 *
 * Everything else in this suite calls the functions the CLI calls. This file
 * runs `dist/cli.js` itself, because the things that can only break there are
 * real: commander's option parsing, the `--no-color` negation, the exit code
 * the shell actually sees, and the fact that `codeguard install` puts a hook on
 * disk. A test that imports `runPatchCommand` cannot tell you that the `patch`
 * command is wired to it — or that `--from-report` survived the trip through
 * commander's camelCase conversion.
 *
 * Requires `dist/` — `npm test` builds first.
 */

import { execFile, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { afterAll, describe, expect, it, jest } from '@jest/globals';

import { EXIT } from '../exit-codes';

/**
 * Every test here runs `dist/cli.js` as a child process, so the same reasoning
 * as the other process-spawning suites applies, with smaller numbers: slowest
 * test 0.7s idle, 1.0s with every core busy, 1.1s with every core busy and the
 * rest of the suite running in parallel. The last is the condition `npm test`
 * creates, and the one the budget is derived from.
 *
 * 12 seconds is ~10x that worst measurement — derived per suite rather than
 * inherited, because this suite spawns one process per test where the hook suite
 * spawns a git repository's worth.
 */
jest.setTimeout(12_000);

const execFileAsync = promisify(execFile);

const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
const BUILT = existsSync(CLI);

if (!BUILT) {
  console.warn(`[cli e2e] skipped: ${CLI} is not built. Run \`npm run build\` first.`);
}

const GIT_AVAILABLE = spawnSync('git', ['--version']).status === 0;

const cleanup: string[] = [];

afterAll(async () => {
  await Promise.all(cleanup.map((dir) => rm(dir, { recursive: true, force: true })));
});

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Runs the CLI exactly as a user would: `node dist/cli.js …`.
 *
 * stdin/stdout are pipes here, never a TTY, which is what makes the
 * non-interactive assertions below true of the real process rather than of a
 * mock of one.
 */
async function cli(args: string[], cwd?: string): Promise<Run> {
  try {
    const { stdout, stderr } = await execFileAsync('node', [CLI, ...args], {
      windowsHide: true,
      ...(cwd === undefined ? {} : { cwd }),
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as { code?: unknown; stdout?: string; stderr?: string };
    return {
      code: typeof failure.code === 'number' ? failure.code : 1,
      stdout: failure.stdout ?? '',
      stderr: failure.stderr ?? '',
    };
  }
}

async function scratchRepo(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'codeguard-cli-'));
  cleanup.push(dir);
  const git = (...args: string[]): Promise<unknown> => execFileAsync('git', args, { cwd: dir, windowsHide: true });
  await git('init', '-q', '.');
  await git('config', 'user.email', 'cli@example.com');
  await git('config', 'user.name', 'CodeGuard CLI');
  await git('config', 'commit.gpgsign', 'false');
  return dir;
}

const maybe = BUILT ? describe : describe.skip;
const maybeGit = BUILT && GIT_AVAILABLE ? describe : describe.skip;

maybe('codeguard --help', () => {
  it('lists the commands', async () => {
    const help = await cli(['--help']);

    expect(help.code).toBe(0);
    for (const command of ['scan', 'patch', 'config', 'install']) {
      expect(help.stdout).toContain(command);
    }
  });

  it('documents patch as interactive and offers the escape hatches', async () => {
    const help = await cli(['patch', '--help']);

    expect(help.code).toBe(0);
    expect(help.stdout).toContain('--from-report');
    expect(help.stdout).toContain('--local');
    expect(help.stdout).toContain('--remote');
  });
});

maybeGit('codeguard patch from a shell', () => {
  it('refuses to hang in a pipeline, and says so as an error not a crash', async () => {
    const repo = await scratchRepo();

    const run = await cli(['patch'], repo);

    // Exit 1, not 2 and not 0: the command could not do its job, which must not
    // be mistakable for "nothing found" by whatever ran it.
    expect(run.code).toBe(EXIT.ERROR);
    expect(run.stderr).toContain('needs a terminal');
  });

  it('accepts --from-report rather than rejecting it as an unknown option', async () => {
    const repo = await scratchRepo();

    const run = await cli(['patch', '--from-report'], repo);

    // The flag parsed — an unknown one never reaches the command body, and the
    // test below shows what that looks like instead.
    expect(run.code).toBe(EXIT.ERROR);
    expect(run.stderr).not.toContain('unknown option');
    // What the body then says is the terminal refusal, not the missing-report
    // message: the TTY guard runs FIRST, deliberately. `--from-report` still
    // prompts, and a command that cannot prompt should say so before it goes
    // looking for a report it will not be able to act on. The flag's own
    // behaviour is covered in patch/__tests__/command.e2e.test.ts, where the
    // interactive seam is injected.
    expect(run.stderr).toContain('needs a terminal');
  });

  it('rejects an unknown option instead of ignoring it', async () => {
    const run = await cli(['patch', '--frm-report']);

    expect(run.code).not.toBe(0);
    expect(run.stderr).toContain('unknown option');
  });
});

maybeGit('codeguard install', () => {
  it('writes the hook and keeps the report out of history', async () => {
    const repo = await scratchRepo();

    const run = await cli(['install'], repo);

    expect(run.code).toBe(0);
    expect(existsSync(path.join(repo, '.git', 'hooks', 'pre-commit'))).toBe(true);
    expect(await readFile(path.join(repo, '.gitignore'), 'utf8')).toBe('.codeguard/\n');
    // Announced, because it is a write to a file the developer owns.
    expect(run.stdout).toContain('added .codeguard/ to .gitignore');
  });

  it('does not append the entry twice when re-run', async () => {
    const repo = await scratchRepo();
    await writeFile(path.join(repo, '.gitignore'), 'node_modules/\n', 'utf8');

    await cli(['install'], repo);
    const second = await cli(['install'], repo);

    expect(second.code).toBe(0);
    expect(await readFile(path.join(repo, '.gitignore'), 'utf8')).toBe('node_modules/\n.codeguard/\n');
    expect(second.stdout).not.toContain('added .codeguard/ to .gitignore');
  });
});
