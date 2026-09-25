/**
 * Both engines against the deliberately vulnerable mini-repo (Phase 6).
 *
 * The rest of this suite tests one thing at a time: a rule against a snippet, a
 * parser against a patch, the patch flow against a scratch file. This file runs
 * the whole of CodeGuard over a whole small repository — the thing a developer
 * actually commits — and holds it to a table of findings written by hand in
 * `test-fixtures/mini-repo/expected.json`.
 *
 * ─── Why the expectations are written, not recorded ──────────────────────────
 * `expected.json` was written by reading the fixtures, not by running the engine
 * over them and saving the output. Expectations generated from an implementation
 * can only detect that it changed; they cannot detect that it is wrong. Every
 * finding is listed with the reason it should be there, so a failure asks a
 * question ("was the rule right, or was the fixture?") instead of answering one.
 *
 * ─── What runs where ─────────────────────────────────────────────────────────
 * Local Mode is run over the entire tree: deterministic, offline, and the place
 * where 13 findings are asserted exactly, line by line, alongside the three
 * files and three individual lines that must stay silent.
 *
 * Remote Mode is run over the two files the recorded answers cover
 * (`test-fixtures/remote/`), replayed through a client that refuses to be
 * anything but a recording of a real provider — including its empty answer and
 * the retry that followed it. The network is never touched.
 *
 * Requires `dist/` — `npm test` builds first.
 */

import { execFile, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { afterAll, describe, expect, it } from '@jest/globals';

import { API_KEY_VAR, type Environment } from '../engine/mode';
import { LlmError, type LlmClient } from '../engine/remote';
import type { LlmRequest } from '../engine/remote/client';
import { EXIT } from '../exit-codes';
import { runPreCommitCheck, scanDiff } from '../hooks/pre-commit';
import { runPatchCommand } from '../patch/command';
import { parseAndRepairPatch } from '../patch/normalise';
import type { ReviewChoice } from '../patch/review';

const execFileAsync = promisify(execFile);

const MINI_REPO = path.resolve(__dirname, '..', '..', 'test-fixtures', 'mini-repo');
const RECORDED = path.resolve(__dirname, '..', '..', 'test-fixtures', 'remote');
const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
const BUILT = existsSync(CLI);

if (!BUILT) {
  console.warn(`[fixtures e2e] skipped: ${CLI} is not built. Run \`npm run build\` first.`);
}

const GIT_AVAILABLE = spawnSync('git', ['--version']).status === 0;

interface Expectation {
  file: string;
  line: number;
  ruleId: string;
  category: string;
  severity: string;
  why: string;
}

interface Expectations {
  findings: Expectation[];
  clean: string[];
  cleanLines: Array<{ file: string; line: number; why: string }>;
  threshold: { blockOn: string; warnOn: string; critical: number; high: number };
}

const expected = JSON.parse(readFileSync(path.join(MINI_REPO, 'expected.json'), 'utf8')) as Expectations;

const cleanup: string[] = [];

afterAll(async () => {
  await Promise.all(cleanup.map((dir) => rm(dir, { recursive: true, force: true })));
});

/** The finding fields `expected.json` makes a claim about. */
interface Shape {
  file: string;
  line: number;
  ruleId: string;
  category: string;
  severity: string;
}

function shape(finding: Expectation): Shape {
  return {
    file: finding.file,
    line: finding.line,
    ruleId: finding.ruleId,
    category: finding.category,
    severity: finding.severity,
  };
}

/** Report order is presentation; the comparison is by position in the file. */
function inFileOrder(findings: readonly Shape[]): Shape[] {
  return [...findings].sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId),
  );
}

interface Repo {
  dir: string;
  diff: string;
  read: (relative: string) => Promise<string>;
}

/**
 * Copies part of the fixture tree into a fresh Git repository and stages it.
 *
 * Staged rather than committed, because that is what CodeGuard is given: the
 * index is the diff a pre-commit hook sees, and every line of a new file is an
 * addition — the strongest case for a scanner to be held to.
 */
async function materialise(relativePaths: readonly string[]): Promise<Repo> {
  const dir = await mkdtemp(path.join(tmpdir(), 'codeguard-fixtures-'));
  cleanup.push(dir);

  const git = async (...args: string[]): Promise<string> => {
    const { stdout } = await execFileAsync('git', args, { cwd: dir, windowsHide: true });
    return stdout;
  };

  await git('init', '-q', '.');
  await git('config', 'user.email', 'fixtures@example.com');
  await git('config', 'user.name', 'CodeGuard fixtures');
  await git('config', 'commit.gpgsign', 'false');
  // The recorded answers were captured against LF content in a repository with
  // this set the same way; without it, Windows would rewrite every line ending
  // and the diff would no longer be the one the answers describe.
  await git('config', 'core.autocrlf', 'false');

  for (const relative of relativePaths) {
    const target = path.join(dir, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await copyFile(path.join(MINI_REPO, relative), target);
  }
  await git('add', ...relativePaths);

  return {
    dir,
    diff: await git('diff', '--cached'),
    read: (relative) => readFile(path.join(dir, relative), 'utf8'),
  };
}

/** Every file in the mini-repo, as repo-relative paths. */
async function allFixtureFiles(): Promise<string[]> {
  async function walk(directory: string): Promise<string[]> {
    const entries = await readdir(directory, { withFileTypes: true });
    const found: string[] = [];
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        found.push(...(await walk(absolute)));
      } else {
        found.push(path.relative(MINI_REPO, absolute).split(path.sep).join('/'));
      }
    }
    return found;
  }
  return (await walk(MINI_REPO)).sort();
}

function capture(): { io: { write: (t: string) => void; writeError: (t: string) => void }; out: () => string; err: () => string } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    io: { write: (text) => void stdout.push(text), writeError: (text) => void stderr.push(text) },
    out: () => stdout.join(''),
    err: () => stderr.join(''),
  };
}

const maybeGit = BUILT && GIT_AVAILABLE ? describe : describe.skip;

// ---------------------------------------------------------------------------
// Local Mode: the whole tree, every finding asserted
// ---------------------------------------------------------------------------

maybeGit('the mini-repo, scanned by the Local static engine', () => {
  it('reports exactly the findings the fixture claims, on exactly the lines it claims', async () => {
    const repo = await materialise(await allFixtureFiles());
    const { io, out } = capture();

    const scan = await runPreCommitCheck({ cwd: repo.dir, local: true, ...io });

    const actual = scan.findings.map((finding) => ({
      file: finding.file,
      line: finding.line,
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
    }));

    // Equality, not containment: an extra finding is as much a failure as a
    // missing one. A detector that reports the negative controls is not being
    // careful, it is being noisy, and noise is how a gate gets switched off.
    expect(inFileOrder(actual)).toEqual(inFileOrder(expected.findings.map(shape)));
    expect(scan.exitCode).toBe(EXIT.BLOCKED);
    expect(out()).toContain('Commit blocked');
  });

  it('says nothing about the files and lines that are safe', async () => {
    const repo = await materialise(await allFixtureFiles());
    const scan = await runPreCommitCheck({ cwd: repo.dir, local: true, ...capture().io });

    const touched = new Set(scan.findings.map((finding) => `${finding.file}:${finding.line}`));
    for (const file of expected.clean) {
      expect(scan.findings.filter((finding) => finding.file === file)).toEqual([]);
    }
    for (const line of expected.cleanLines) {
      // Stated per line rather than per file, because these are the lines whose
      // neighbours ARE reported: the safe query three lines below the injected
      // one is the assertion that the rule is reading, not just matching a word.
      expect(touched.has(`${line.file}:${line.line}`)).toBe(false);
    }
  });

  it('splits the findings into the counts the threshold acts on', async () => {
    const repo = await materialise(await allFixtureFiles());
    const scan = await runPreCommitCheck({ cwd: repo.dir, local: true, ...capture().io });

    const critical = scan.findings.filter((finding) => finding.severity === 'Critical').length;
    const high = scan.findings.filter((finding) => finding.severity === 'High').length;

    expect({ critical, high }).toEqual({
      critical: expected.threshold.critical,
      high: expected.threshold.high,
    });
    // Block on Critical, warn on High: the High findings are reported and the
    // commit is blocked by the Critical ones, which is the configured policy and
    // not a coincidence of this fixture.
    expect(scan.decision.blocking.length).toBe(expected.threshold.critical);
    expect(scan.decision.warned.length).toBe(expected.threshold.high);
  });

  it('blocks a real commit through the CLI, in the repository it is pointed at', async () => {
    const repo = await materialise(await allFixtureFiles());

    const run = await cli(['scan', '--local', '--staged'], repo.dir);

    expect(run.code).toBe(EXIT.BLOCKED);

    // The report groups by file and prints `line  severity  ruleId` beneath each
    // heading (report/render.ts), so the assertion is written in that shape
    // rather than as `file:line`. These two lines are the headline: the SQL
    // injection the developer introduced in a route, and the AWS key id in the
    // config file, at the lines the fixture table claims.
    expect(run.stdout).toMatch(/^\s+14\s+Critical\s+sql-string-concatenation$/m);
    expect(run.stdout).toMatch(/^\s+13\s+Critical\s+hardcoded-secret-aws-key$/m);

    // Then every finding in the table, so a CLI that rendered a subset of what
    // the engine found cannot pass on the two lines above alone.
    for (const finding of expected.findings) {
      expect(run.stdout).toContain(finding.file);
      expect(run.stdout).toContain(finding.ruleId);
    }
  });
});

async function cli(args: string[], cwd: string): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync('node', [CLI, ...args], { cwd, windowsHide: true });
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

// ---------------------------------------------------------------------------
// Remote Mode: the recorded answers, replayed
// ---------------------------------------------------------------------------

/** The two files the recording covers, per test-fixtures/remote/README.md. */
const COVERED = ['src/routes/users.js', 'src/config.js'];

/** `git diff` writes a line naming the blobs; nothing else about it varies. */
function withoutIndexLines(diff: string): string {
  return diff
    .split('\n')
    .filter((line) => !line.startsWith('index '))
    .join('\n');
}

async function recorded(file: string): Promise<string> {
  return readFile(path.join(RECORDED, file), 'utf8');
}

/**
 * A client that answers from the recording and nothing else.
 *
 * The script is one entry LONGER than `deep.json`: the recording's first
 * Stage-2 answer is missing because the provider answered nothing at all, and an
 * empty answer reaches the pipeline as a thrown error rather than a value. The
 * leading `''` reproduces that, and the retry is what the recording caught.
 */
function replayClient(options: { script: string[]; requests: LlmRequest[]; triage: string }): LlmClient {
  const queue = [...options.script];
  return {
    model: 'deepseek-flash (recorded 2026-09-25)',
    complete: async (request: LlmRequest): Promise<string> => {
      options.requests.push(request);
      if (!request.reasoning) return options.triage;

      const next = queue.shift();
      if (next === undefined) {
        throw new Error('the pipeline asked for more deep answers than the recording holds');
      }
      if (next === '') throw new LlmError('the provider returned an empty answer', 'empty');
      return next;
    },
  };
}

async function recordedScript(): Promise<string[]> {
  const answers = JSON.parse(await recorded('deep.json')) as string[];
  return ['', ...answers];
}

function environmentWithKey(): Environment {
  return { env: { [API_KEY_VAR]: 'sk-recorded-not-used' }, envFile: null, fromFile: [] };
}

/**
 * Runs the recorded scan and returns everything the pipeline put in a prompt.
 *
 * Used by the two redaction tests. The recording has to be replayed rather than
 * a diff fabricated, because the redaction pass runs inside the remote pipeline
 * — the only way to see what it sends is to let it send it.
 */
async function promptsSent(repo: Repo): Promise<string> {
  const requests: LlmRequest[] = [];
  await scanDiff({
    diff: repo.diff,
    repoRoot: repo.dir,
    remote: true,
    environment: environmentWithKey(),
    client: replayClient({
      script: await recordedScript(),
      requests,
      triage: (JSON.parse(await recorded('triage.json')) as string[])[0] ?? '',
    }),
    ...capture().io,
  });
  return requests.map((request) => request.user).join('\n');
}

maybeGit('the mini-repo, scanned in Remote Mode against the recorded answers', () => {
  it('rebuilds the diff the answers were recorded against', async () => {
    const repo = await materialise(COVERED);

    // The guard that makes the rest of this block meaningful. A triage answer
    // names line ranges and a Stage-2 answer names a hunk; replay them against
    // different content and the assertions below would be describing a scan that
    // never happened.
    expect(withoutIndexLines(repo.diff)).toBe(withoutIndexLines(await recorded('diff.patch')));
  });

  it('redacts the credentials out of the diff before it is sent', async () => {
    const repo = await materialise(COVERED);

    const sent = await promptsSent(repo);

    // FR-4 and NFR §8, end to end: the values in config.js are in the diff, the
    // pipeline sends the diff, and the values the redactor claims are not in what
    // it sends.
    expect(sent).toContain('«REDACTED:');
    expect(sent).not.toContain('sk_live_9f8a7b6c5d4e3f2a1b0c');
    expect(sent).not.toContain('AKIAIOSFODNN7EXAMPLE');
    // The scope boundary, over the real recording: the injection the model is
    // being asked to fix arrives intact, quotes and all. Only credentials are
    // withheld — redacting the vulnerability would remove the thing under review.
    expect(sent).toContain('SELECT id, email FROM users WHERE id =');
    // And the diff on disk is untouched: redaction is about transmission, never
    // about what the developer has staged.
    expect(await repo.read('src/config.js')).toContain('sk_live_9f8a7b6c5d4e3f2a1b0c');
  });

  /**
   * The case that put the rule-engine floor into the redaction pass.
   *
   * `dbPassword: "Spr1ng2024!prod"` is 15 characters and its identifier carries
   * a prefix, so every heuristic in `engine/remote/redact.ts` walks past it: the
   * generic assignment pattern's lookbehind needs `\bpassword\b` and `dbPassword`
   * has no boundary there, and the entropy backstop's quoted-value floor is 20
   * characters. The rule engine flags the line anyway — its pattern needs no word
   * boundary — and before the floor existed this literal reached the provider in
   * plaintext, which this test asserted as a known gap.
   *
   * It reads the other way now. The finding is what withholds the value, not a
   * shorter floor and not a wider pattern: the heuristics are unchanged, and the
   * named recognisers still label their own.
   */
  it('withholds a short password-shaped literal the heuristics would have missed', async () => {
    const repo = await materialise(COVERED);

    const sent = await promptsSent(repo);

    expect(sent).not.toContain('Spr1ng2024!prod');
    expect(sent).toContain('«REDACTED:known-secret»');
    // The other two credentials in the same file keep the labels their
    // recognisers gave them: the floor is an addition, not a replacement.
    expect(sent).toContain('«REDACTED:stripe-key»');
    expect(sent).toContain('«REDACTED:aws-access-key»');
  });

  it('keeps the rule engine`s findings when the model declines to confirm them', async () => {
    const repo = await materialise(COVERED);
    const requests: LlmRequest[] = [];
    const scan = await scanDiff({
      diff: repo.diff,
      repoRoot: repo.dir,
      remote: true,
      environment: environmentWithKey(),
      client: replayClient({
        script: await recordedScript(),
        requests,
        triage: (JSON.parse(await recorded('triage.json')) as string[])[0] ?? '',
      }),
      ...capture().io,
    });

    // The recorded deep answer calls config.js's credentials a false positive —
    // with a good argument, since the file says so in its own comments. The floor
    // in engine/reconcile.ts keeps them anyway, and this is the assertion that
    // the floor is load-bearing rather than decorative.
    const secrets = scan.findings.filter((finding) => finding.category === 'hardcoded_secret');
    expect(secrets).toHaveLength(3);
    expect(scan.notes.some((note) => note.includes('not allowed to produce a weaker result'))).toBe(true);

    // Triage did flag users.js, so the sql_injection findings are there twice
    // over — once from the model and once from the rules — and are not
    // duplicated in the report.
    const injections = scan.findings.filter((finding) => finding.category === 'sql_injection');
    expect(injections.length).toBeGreaterThan(0);
    expect(scan.exitCode).toBe(EXIT.BLOCKED);

    // The retry is part of the recording, and it happened: two Stage-2 requests
    // for config.js and one for users.js, so three reasoning calls in all.
    expect(requests.filter((request) => request.reasoning)).toHaveLength(3);
  });

  it('offers a patch for the file the model patched, and none for the file it cleared', async () => {
    const repo = await materialise(COVERED);
    const requests: LlmRequest[] = [];
    const scan = await scanDiff({
      diff: repo.diff,
      repoRoot: repo.dir,
      remote: true,
      environment: environmentWithKey(),
      client: replayClient({
        script: await recordedScript(),
        requests,
        triage: (JSON.parse(await recorded('triage.json')) as string[])[0] ?? '',
      }),
      ...capture().io,
    });

    expect(scan.analyses).toHaveLength(1);
    const analysis = scan.analyses[0];
    expect(analysis?.file).toBe('src/routes/users.js');
    expect(analysis?.patch.trim()).not.toBe('');

    // This particular answer was well-formed. It is asserted rather than assumed
    // because the repair pipeline must stay ready for the ones that are not —
    // see the note in normalise.ts — and a fixture that quietly needed repair
    // would stop being evidence either way.
    const parsed = parseAndRepairPatch(analysis?.patch ?? '', 'src/routes/users.js');
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.patch.repairs).toEqual([]);
  });

  it('names the patchless findings when the review flow opens', async () => {
    const repo = await materialise(COVERED);
    const { io, out } = capture();
    const answers: ReviewChoice[] = ['skip', 'skip'];

    const code = await runPatchCommand({
      cwd: repo.dir,
      environment: environmentWithKey(),
      client: replayClient({
        script: await recordedScript(),
        requests: [],
        triage: (JSON.parse(await recorded('triage.json')) as string[])[0] ?? '',
      }),
      ask: async () => answers.shift() ?? 'skip',
      ...io,
    });

    // The recorded run is exactly the shape this was built for: config.js has
    // three findings and no analysis, because its deep answer was discarded as a
    // false positive and the floor put the findings back. Before, those three
    // would have been invisible; the developer would have been asked about one
    // file and told nothing about the other.
    expect(out()).toContain('came back with no patch');
    expect(out()).toContain('src/config.js:11');
    expect(code).toBe(EXIT.BLOCKED);
  });
});
