/**
 * End-to-end verification of FR-2 / FR-9 — the Phase 3 acceptance criterion:
 * "a real `git commit` in a scratch test repo actually triggers the hook and
 * blocks a seeded-bad commit."
 *
 * These tests therefore do no mocking. Each creates a real repository in a temp
 * directory, runs real `git` commands, and lets the installed hook execute the
 * real built CLI as a separate process. That is the only way to cover the parts
 * that unit tests structurally cannot reach: that Git finds the hook, that the
 * shell script parses, that the exit code propagates, and that the commit is
 * actually refused.
 *
 * Requires `dist/` to be built — `npm test` builds first. Running `npm run
 * test:only` without a build skips this file with a printed explanation rather
 * than failing confusingly.
 */

import { execFile, spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { afterAll, describe, expect, it } from '@jest/globals';

import { CONFIG_FILENAME } from '../../config/schema';
import { BACKUP_SUFFIX, HOOK_MARKER, installPreCommitHook } from '../pre-commit';

const execFileAsync = promisify(execFile);

/** The built CLI — the artefact users actually run, not the TypeScript source. */
const CLI_PATH = path.resolve(__dirname, '..', '..', '..', 'dist', 'cli.js');

const CLI_BUILT = existsSync(CLI_PATH);
const GIT_AVAILABLE = spawnSync('git', ['--version']).status === 0;

if (!CLI_BUILT) {
  console.warn(`[pre-commit e2e] skipped: ${CLI_PATH} is not built. Run \`npm run build\` first.`);
}

const cleanup: string[] = [];

afterAll(async () => {
  await Promise.all(cleanup.map((dir) => rm(dir, { recursive: true, force: true })));
});

interface RunResult {
  code: number;
  output: string;
}

async function run(cwd: string, file: string, args: string[]): Promise<RunResult> {
  try {
    const { stdout, stderr } = await execFileAsync(file, args, { cwd, windowsHide: true });
    return { code: 0, output: `${stdout}${stderr}` };
  } catch (error) {
    const failure = error as { code?: unknown; stdout?: string; stderr?: string };
    return {
      code: typeof failure.code === 'number' ? failure.code : 1,
      output: `${failure.stdout ?? ''}${failure.stderr ?? ''}`,
    };
  }
}

interface Repo {
  dir: string;
  git: (...args: string[]) => Promise<RunResult>;
  /** Writes a file (creating parent directories) and stages it. */
  stage: (relative: string, contents: string) => Promise<void>;
  commit: (message: string, ...extra: string[]) => Promise<RunResult>;
  commitCount: () => Promise<number>;
  head: () => Promise<string>;
  /** Installs the hook, asserting it went to the native path. */
  installHook: () => Promise<void>;
}

async function setupRepo(): Promise<Repo> {
  const dir = await mkdtemp(path.join(tmpdir(), 'codeguard-e2e-'));
  cleanup.push(dir);

  const git = (...args: string[]): Promise<RunResult> => run(dir, 'git', args);
  await git('init', '-q', '.');
  await git('config', 'user.email', 'e2e@example.com');
  await git('config', 'user.name', 'CodeGuard E2E');
  await git('config', 'commit.gpgsign', 'false');
  // Keep the diff byte-for-byte identical on every platform, so a failure here
  // is a real failure rather than a line-ending artefact.
  await git('config', 'core.autocrlf', 'false');

  const stage = async (relative: string, contents: string): Promise<void> => {
    const target = path.join(dir, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, contents, 'utf8');
    await git('add', relative);
  };

  const commit = (message: string, ...extra: string[]): Promise<RunResult> =>
    git('commit', '-q', '-m', message, ...extra);

  const commitCount = async (): Promise<number> =>
    Number.parseInt((await git('rev-list', '--count', 'HEAD')).output.trim(), 10);

  const head = async (): Promise<string> => (await git('log', '-1', '--format=%s')).output.trim();

  const installHook = async (): Promise<void> => {
    const result = await installPreCommitHook(dir);
    expect(result.mechanism).toBe('native');
    expect(result.hookPath).toBe(path.join(dir, '.git', 'hooks', 'pre-commit'));
  };

  const repo: Repo = { dir, git, stage, commit, commitCount, head, installHook };

  // Baseline commit BEFORE the hook exists, so setup is never itself blocked.
  await stage('README.md', '# scratch\n');
  await commit('baseline');

  // The hook resolves ./node_modules/.bin/codeguard first. Dropping a shim there
  // is exactly what a real project dependency install produces, and it keeps
  // these tests independent of whatever `codeguard` happens to be on PATH.
  const binDir = path.join(dir, 'node_modules', '.bin');
  await mkdir(binDir, { recursive: true });
  const shim = path.join(binDir, 'codeguard');
  const posixCli = CLI_PATH.split(path.sep).join('/');
  await writeFile(shim, `#!/usr/bin/env sh\nexec node "${posixCli}" "$@"\n`, 'utf8');
  await chmod(shim, 0o755);

  return repo;
}

/** A change the Local Engine is guaranteed to flag as Critical. */
const SEEDED_SQLI = 'const q = "SELECT id FROM users WHERE id = " + userId;\n';
/** A change the Local Engine flags as High, but not Critical. */
const SEEDED_STRCPY = 'void copy(char *d, const char *s) {\n  strcpy(d, s);\n}\n';

const maybe = CLI_BUILT && GIT_AVAILABLE ? describe : describe.skip;

maybe('pre-commit hook, end to end', () => {
  it('blocks a commit that introduces a Critical finding, and nothing is committed', async () => {
    const repo = await setupRepo();
    await repo.installHook();
    const before = await repo.commitCount();

    await repo.stage('db.js', SEEDED_SQLI);
    const result = await repo.commit('seeded sql injection');

    expect(result.code).not.toBe(0);
    expect(result.output).toContain('Commit blocked');
    expect(result.output).toContain('sql-string-concatenation');
    expect(await repo.commitCount()).toBe(before);
    expect(await repo.head()).toBe('baseline');
  });

  it('allows a clean commit, and says so', async () => {
    const repo = await setupRepo();
    await repo.installHook();

    await repo.stage('util.js', 'const total = items.reduce((sum, item) => sum + item.price, 0);\n');
    const result = await repo.commit('clean change');

    expect(result.output).toContain('no issues found');
    expect(await repo.head()).toBe('clean change');
  });

  it('allows a commit whose only findings are warnings, not blocks', async () => {
    // strcpy is High. The default threshold blocks on Critical only, so this
    // must pass with a warning — the difference between the two thresholds is
    // the whole point of having two.
    const repo = await setupRepo();
    await repo.installHook();

    await repo.stage('copy.c', SEEDED_STRCPY);
    const result = await repo.commit('high but not critical');

    expect(result.output).toContain('Commit allowed');
    expect(await repo.head()).toBe('high but not critical');
  });

  it('lets --no-verify through, because that is Git`s own escape hatch (PRD §11)', async () => {
    const repo = await setupRepo();
    await repo.installHook();

    await repo.stage('db.js', SEEDED_SQLI);
    const result = await repo.commit('bypassing', '--no-verify');

    expect(result.code).toBe(0);
    expect(await repo.head()).toBe('bypassing');
  });

  it('reports exit code 3 for a blocking scan, distinct from a crash', async () => {
    // Git normalises every non-zero hook status to 1, so the distinction is
    // only observable by invoking the CLI directly — which is what a wrapper
    // script or CI job would do.
    const repo = await setupRepo();
    await repo.installHook();
    await repo.stage('db.js', SEEDED_SQLI);

    const result = await run(repo.dir, 'node', [CLI_PATH, 'scan', '--staged']);
    expect(result.code).toBe(3);
  });

  it('reports exit code 0 for a clean scan', async () => {
    const repo = await setupRepo();
    await repo.installHook();
    await repo.stage('ok.js', 'const ok = 1;\n');

    const result = await run(repo.dir, 'node', [CLI_PATH, 'scan', '--staged']);
    expect(result.code).toBe(0);
  });

  it('is idempotent — re-installing leaves exactly one scan invocation', async () => {
    const repo = await setupRepo();
    await repo.installHook();
    const first = await readFile(path.join(repo.dir, '.git', 'hooks', 'pre-commit'), 'utf8');

    await repo.installHook();
    await repo.installHook();
    const third = await readFile(path.join(repo.dir, '.git', 'hooks', 'pre-commit'), 'utf8');

    expect(third).toBe(first);
    expect(third.split(HOOK_MARKER)).toHaveLength(2); // the marker appears once
    // The exec line, not the bare words — those also appear in the header comment.
    expect(third.split('exec "$CODEGUARD" scan --staged')).toHaveLength(2);
  });

  it('preserves a pre-existing hook, and keeps running it', async () => {
    const repo = await setupRepo();
    const hookPath = path.join(repo.dir, '.git', 'hooks', 'pre-commit');
    await mkdir(path.dirname(hookPath), { recursive: true });
    await writeFile(
      hookPath,
      '#!/bin/sh\necho "EXISTING-HOOK-RAN" >> .hook-evidence\nexit 0\n',
      'utf8',
    );
    await chmod(hookPath, 0o755);

    const result = await installPreCommitHook(repo.dir);
    expect(result.action).toBe('wrapped');
    expect(result.backupPath).toBe(`${hookPath}${BACKUP_SUFFIX}`);
    // The original is preserved verbatim, not paraphrased.
    expect(await readFile(result.backupPath!, 'utf8')).toContain('EXISTING-HOOK-RAN');

    // A clean commit must run both: the preserved hook writes its evidence, and
    // CodeGuard reports. Overwriting would have silently disabled it.
    await repo.stage('ok.js', 'const ok = 1;\n');
    const commit = await repo.commit('clean');
    expect(commit.code).toBe(0);
    expect(await readFile(path.join(repo.dir, '.hook-evidence'), 'utf8')).toContain(
      'EXISTING-HOOK-RAN',
    );
    expect(commit.output).toContain('no issues found');
  });

  it('still runs a preserved hook after the hook is re-installed', async () => {
    // The regression this guards: re-installing rewrites the script from scratch.
    // If it forgot the backup, the wrapper would stop calling the preserved hook
    // and the developer's existing gate would go quiet with no error at all.
    const repo = await setupRepo();
    const hookPath = path.join(repo.dir, '.git', 'hooks', 'pre-commit');
    await mkdir(path.dirname(hookPath), { recursive: true });
    await writeFile(hookPath, '#!/bin/sh\necho "EXISTING-HOOK-RAN" >> .hook-evidence\n', 'utf8');
    await chmod(hookPath, 0o755);

    await installPreCommitHook(repo.dir);
    await installPreCommitHook(repo.dir);
    await installPreCommitHook(repo.dir);

    await repo.stage('ok.js', 'const ok = 1;\n');
    expect((await repo.commit('clean')).code).toBe(0);
    expect(await readFile(path.join(repo.dir, '.hook-evidence'), 'utf8')).toContain(
      'EXISTING-HOOK-RAN',
    );
  });

  it('honours blockOn from the config file', async () => {
    const repo = await setupRepo();
    await repo.installHook();
    // Not staged, so the config itself never appears in the diff under test.
    await writeFile(
      path.join(repo.dir, CONFIG_FILENAME),
      JSON.stringify({ threshold: { blockOn: 'High' } }),
      'utf8',
    );

    await repo.stage('copy.c', SEEDED_STRCPY);
    const result = await repo.commit('high now blocks');

    expect(result.code).not.toBe(0);
    expect(result.output).toContain('block threshold "High"');
  });

  it('honours excludePaths from the config file', async () => {
    const repo = await setupRepo();
    await repo.installHook();
    await writeFile(
      path.join(repo.dir, CONFIG_FILENAME),
      JSON.stringify({ excludePaths: ['generated/**'] }),
      'utf8',
    );

    await repo.stage('generated/bundle.js', SEEDED_SQLI);
    const result = await repo.commit('excluded path');

    expect(result.code).toBe(0);
    expect(result.output).toContain('no issues found');
  });

  it('warns loudly about a malformed config but still applies the default threshold', async () => {
    // A typo'd config must not quietly turn the gate into a no-op. The scan
    // still runs, the defaults still block, and the warning repeats every commit
    // until the file is fixed.
    const repo = await setupRepo();
    await repo.installHook();
    await writeFile(
      path.join(repo.dir, CONFIG_FILENAME),
      JSON.stringify({ threshold: { blockOn: 'Critcal' } }),
      'utf8',
    );

    await repo.stage('db.js', SEEDED_SQLI);
    const result = await repo.commit('malformed config');

    expect(result.output).toContain('threshold.blockOn');
    expect(result.output).toContain('must be one of');
    expect(result.code).not.toBe(0);
    expect(result.output).toContain('Commit blocked');
  });

  it('allows the commit, loudly, when the CLI cannot be found at all', async () => {
    // The documented failure policy: an un-installed or moved CLI must not make
    // a repository permanently un-committable, but it must never be silent.
    //
    // Without controlling PATH this test would find whatever `codeguard` happens
    // to be installed on the machine running it, and would pass or fail by
    // accident. The environment is overridden *inside* a wrapper script rather
    // than by passing an env to spawn: replacing PATH means Node can no longer
    // resolve `sh` to spawn in the first place, so the child dies before the
    // hook is reached and the failure looks like an empty, successful run.
    const repo = await setupRepo();
    await repo.installHook();
    // Remove the shim, so the ./node_modules/.bin branch cannot succeed either.
    await rm(path.join(repo.dir, 'node_modules'), { recursive: true, force: true });
    await repo.stage('db.js', SEEDED_SQLI);

    const hookPath = path.join(repo.dir, '.git', 'hooks', 'pre-commit').split(path.sep).join('/');
    const wrapper = path.join(repo.dir, 'isolated-hook.sh');
    await writeFile(
      wrapper,
      [
        '#!/usr/bin/env sh',
        '# Runs the installed hook with every CLI-resolution branch forced to fail.',
        'PATH=/nonexistent',
        'export PATH',
        'CODEGUARD_BIN=/nonexistent/codeguard',
        'export CODEGUARD_BIN',
        `. "${hookPath}"`,
        '',
      ].join('\n'),
      'utf8',
    );

    const isolated = await run(repo.dir, 'sh', [wrapper]);

    expect(isolated.code).toBe(0);
    expect(isolated.output).toContain('NO security check ran');
  });

  it('writes to .husky/pre-commit, not the generated shim, in a Husky repo', async () => {
    const repo = await setupRepo();
    // What `husky init` does in v9: point core.hooksPath at .husky/_ and put a
    // generated shim there that sources the user-editable hook one level up.
    await repo.git('config', 'core.hooksPath', '.husky/_');
    const huskyDir = path.join(repo.dir, '.husky');
    await mkdir(path.join(huskyDir, '_'), { recursive: true });
    await writeFile(
      path.join(huskyDir, '_', 'pre-commit'),
      '#!/usr/bin/env sh\necho "HUSKY-SHIM-RAN" >> .hook-evidence\n. "$(dirname "$0")/../pre-commit"\n',
      'utf8',
    );
    await chmod(path.join(huskyDir, '_', 'pre-commit'), 0o755);

    const result = await installPreCommitHook(repo.dir);
    expect(result.mechanism).toBe('husky');
    expect(result.hookPath).toBe(path.join(huskyDir, 'pre-commit'));
    // Writing the shim instead would be undone the next time Husky runs.
    expect(await readFile(path.join(huskyDir, '_', 'pre-commit'), 'utf8')).toContain('HUSKY-SHIM-RAN');

    // And the hook actually fires through the shim.
    await repo.stage('db.js', SEEDED_SQLI);
    const commit = await repo.commit('seeded via husky');
    expect(commit.code).not.toBe(0);
    expect(commit.output).toContain('Commit blocked');
  });
});
