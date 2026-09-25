/**
 * `codeguard patch`, end to end (FR-7, and the Phase 5 acceptance criterion:
 * "accepting a suggested patch correctly modifies the file on disk and the diff
 * is re-stageable").
 *
 * A real repository, a real file on disk, real `git add`, the real diff
 * applier, and the real re-scan. The only things stubbed are the three
 * interactive seams (so no test opens a TTY or an editor) and the provider (so
 * no test reaches the network).
 *
 * ─── Why the provider stub is conditional ────────────────────────────────────
 * It answers from the CONTENT it was asked about, not from a fixed script. That
 * is what makes the re-scan assertion mean something: the second scan must see
 * the fixed file, so the stub only reports the injection while the injection is
 * actually in the diff. A stub with one canned answer would let the command
 * "clear" the commit without the file having changed at all — which is the
 * exact failure the re-scan exists to prevent.
 */

import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { afterAll, describe, expect, it, jest } from '@jest/globals';

import type { Environment } from '../../engine/mode';
import { API_KEY_VAR } from '../../engine/mode';
import { LlmError, type LlmClient } from '../../engine/remote';
import type { LlmRequest } from '../../engine/remote/client';
import { EXIT } from '../../exit-codes';
import { scanDiff } from '../../hooks/pre-commit';
import { runPatchCommand } from '../command';
import type { ReviewChoice, ReviewQuestion } from '../review';

/**
 * Jest's 5-second default is a unit-test budget; these tests create a real
 * repository and spawn real `git` processes, so their cost tracks how busy the
 * machine is rather than how much work they do. Measured here: slowest test
 * 0.8s idle, 1.1s with every core busy, 1.3s with every core busy and the rest
 * of the suite running in parallel — the last being the condition this runs
 * under in `npm test`, and the one the budget is derived from.
 *
 * 15 seconds is ~10x that worst measurement. Same reasoning as
 * `hooks/__tests__/pre-commit.e2e.test.ts`, derived from this suite's own
 * numbers: enough that scheduling alone cannot fail it, small enough that a real
 * hang is still reported as a hang rather than as slowness.
 */
jest.setTimeout(15_000);

const execFileAsync = promisify(execFile);

const GIT_AVAILABLE = spawnSync('git', ['--version']).status === 0;

const KEY = 'sk-live-9f2b7c41d8e35a60b4c7f1e2';
const TARGET = 'server/routes/users.js';

/**
 * The file under test. Line 6 is the injection; every line is added, because
 * the file is new to the repository, which is the strongest case for the
 * scanner to reason about.
 */
const VULNERABLE = [
  "const express = require('express');",
  'const router = express.Router();',
  '',
  "router.get('/users/:id', (req, res) => {",
  '  const userId = req.params.id;',
  '  const sql = "SELECT id, email FROM users WHERE id = " + userId;',
  '  db.query(sql, (err, rows) => res.json(rows));',
  '});',
  '',
  'module.exports = router;',
  '',
].join('\n');

/** The line count the file has after the patch below is applied. */
const FIXED_QUERY_LINE =
  '  db.query("SELECT id, email FROM users WHERE id = ?", [userId], (err, rows) => res.json(rows));';

/**
 * What the live provider returns for this shape of hunk: correct content, no
 * file header, and a new-side count one too high. Both defects are repaired by
 * the pipeline before the developer ever sees them, and the e2e proves they are
 * repaired on the real path rather than only in normalise.ts's own tests.
 */
const MODEL_PATCH = [
  '@@ -3,5 +3,5 @@',
  " router.get('/users/:id', (req, res) => {",
  '   const userId = req.params.id;',
  '-  const sql = "SELECT id, email FROM users WHERE id = " + userId;',
  '-  db.query(sql, (err, rows) => res.json(rows));',
  `+${FIXED_QUERY_LINE}`,
  ' });',
].join('\n');

function triageAnswer(vulnerable: boolean): string {
  return JSON.stringify({
    findings: vulnerable
      ? [
          {
            file: TARGET,
            line_range: [6, 6],
            severity: 'Critical',
            category: 'sql_injection',
            summary: 'User input is concatenated into the query string.',
          },
        ]
      : [],
  });
}

function deepAnswer(): string {
  return JSON.stringify({
    file: TARGET,
    line_range: [6, 6],
    severity: 'Critical',
    category: 'sql_injection',
    explanation: 'The id parameter is concatenated straight into the SQL text.',
    suggested_patch: MODEL_PATCH,
    confidence: 'high',
  });
}

interface Stub {
  client: LlmClient;
  /** Every request, in order, so a test can assert what each scan was shown. */
  requests: LlmRequest[];
  triagePrompts: () => string[];
}

/**
 * Answers triage from the diff it was given, and deep analysis from a constant.
 *
 * `deep` is thrown away by the pipeline when triage reported nothing, so the
 * canned patch can only ever be used for a hunk that is still vulnerable.
 */
function stub(): Stub {
  const requests: LlmRequest[] = [];
  return {
    requests,
    triagePrompts: () =>
      requests.filter((request) => !request.reasoning).map((request) => request.user),
    client: {
      model: 'stub-model',
      complete: async (request: LlmRequest): Promise<string> => {
        requests.push(request);
        if (request.reasoning) return deepAnswer();
        return triageAnswer(request.user.includes('" + userId'));
      },
    },
  };
}

const cleanup: string[] = [];

afterAll(async () => {
  await Promise.all(cleanup.map((dir) => rm(dir, { recursive: true, force: true })));
});

interface Repo {
  dir: string;
  /** Writes the vulnerable file and stages it. */
  stageVulnerable: () => Promise<void>;
  run: (...args: string[]) => Promise<string>;
  /** The staged diff, as Git would show it to the hook. */
  stagedDiff: () => Promise<string>;
  read: (relative: string) => Promise<string>;
}

async function setupRepo(): Promise<Repo> {
  const dir = await mkdtemp(path.join(tmpdir(), 'codeguard-patch-e2e-'));
  cleanup.push(dir);

  const git = async (...args: string[]): Promise<string> => {
    const { stdout } = await execFileAsync('git', args, { cwd: dir, windowsHide: true });
    return stdout;
  };

  await git('init', '-q', '.');
  await git('config', 'user.email', 'e2e@example.com');
  await git('config', 'user.name', 'CodeGuard E2E');
  await git('config', 'commit.gpgsign', 'false');
  await git('config', 'core.autocrlf', 'false');

  const write = async (relative: string, contents: string): Promise<void> => {
    const target = path.join(dir, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, contents, 'utf8');
  };

  await write('README.md', '# scratch\n');
  await git('add', 'README.md');
  await git('commit', '-q', '-m', 'baseline');

  return {
    dir,
    run: git,
    stageVulnerable: async () => {
      await write(TARGET, VULNERABLE);
      await git('add', TARGET);
    },
    stagedDiff: () => git('diff', '--cached'),
    read: (relative: string) => readFile(path.join(dir, relative), 'utf8'),
  };
}

function environmentWithKey(): Environment {
  return { env: { [API_KEY_VAR]: KEY }, envFile: null, fromFile: [] };
}

/** Captures the command's output so it can be asserted on. */
function capture(): { io: { write: (t: string) => void; writeError: (t: string) => void }; out: () => string; err: () => string } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    io: { write: (text) => void stdout.push(text), writeError: (text) => void stderr.push(text) },
    out: () => stdout.join(''),
    err: () => stderr.join(''),
  };
}

/**
 * Scripts the answers, and records what the developer was asked.
 *
 * The questions are kept, not just counted, because some of this file's claims
 * are about what the review OFFERED — a finding with no patch must not be shown
 * an [a]pply option, and the reason it has none has to reach the prompt.
 */
function scriptedAsk(answers: ReviewChoice[]): {
  ask: (question: ReviewQuestion) => Promise<ReviewChoice>;
  asked: () => number;
  questions: () => ReviewQuestion[];
} {
  const queue = [...answers];
  const seen: ReviewQuestion[] = [];
  return {
    ask: async (question) => {
      seen.push(question);
      const next = queue.shift();
      if (next === undefined) throw new Error('the command asked more questions than the test scripted');
      return next;
    },
    asked: () => seen.length,
    questions: () => seen,
  };
}

const maybe = GIT_AVAILABLE ? describe : describe.skip;

maybe('codeguard patch, end to end', () => {
  it('applies an accepted patch to the file, stages it, and re-checks the staged diff', async () => {
    const repo = await setupRepo();
    await repo.stageVulnerable();

    const before = await repo.read(TARGET);
    expect(before).toContain('"SELECT id, email FROM users WHERE id = " + userId;');

    const provider = stub();
    const { io, out, err } = capture();
    const { ask, asked } = scriptedAsk(['apply']);

    const code = await runPatchCommand({
      cwd: repo.dir,
      environment: environmentWithKey(),
      client: provider.client,
      ask,
      ...io,
    });

    // 1. The file on disk is fixed. The model's patch had no file header and a
    //    wrong new-side count, so this also proves parse-and-repair ran on the
    //    real path — nothing else could have made that patch apply.
    const after = await repo.read(TARGET);
    expect(after).toContain(FIXED_QUERY_LINE);
    expect(after).not.toContain('" + userId');
    expect(err()).toContain('repaired the patch');

    // 2. The fix is STAGED. The pre-commit gate reads the index, so a fix that
    //    only exists in the working tree would leave the developer blocked with
    //    a file that no longer contains the vulnerability.
    const staged = await repo.stagedDiff();
    expect(staged).toContain(`+${FIXED_QUERY_LINE}`);
    expect(staged).not.toContain('" + userId');

    // 3. The re-scan saw the NEW content — and only a conditional provider can
    //    tell us that, which is why the stub reads the diff it is given.
    const prompts = provider.triagePrompts();
    expect(prompts).toHaveLength(2);
    expect(prompts[0]).toContain('" + userId');
    expect(prompts[1]).not.toContain('" + userId');
    expect(prompts[1]).toContain('WHERE id = ?');

    // 4. And the gate is clear, so the developer can commit.
    expect(code).toBe(EXIT.OK);
    expect(out()).toContain('applied the patch to server/routes/users.js');
    expect(out()).toContain('staged 1 changed file');
    expect(out()).toContain('the staged changes are clean now');
    expect(asked()).toBe(1);
  });

  it('writes nothing when the patch is skipped, and the commit stays blocked', async () => {
    const repo = await setupRepo();
    await repo.stageVulnerable();

    const provider = stub();
    const { io, out } = capture();
    const { ask } = scriptedAsk(['skip']);

    const code = await runPatchCommand({
      cwd: repo.dir,
      environment: environmentWithKey(),
      client: provider.client,
      ask,
      ...io,
    });

    expect(await repo.read(TARGET)).toBe(VULNERABLE);
    expect(await repo.stagedDiff()).toContain('" + userId');
    expect(code).toBe(EXIT.BLOCKED);
    expect(out()).toContain('nothing was applied, so the verdict above still stands');
    // One scan: with nothing applied there is nothing to re-check, and a second
    // remote scan would cost a round trip to re-derive the same answer.
    expect(provider.triagePrompts()).toHaveLength(1);
  });

  it('lets the developer edit the model`s patch before it is written', async () => {
    const repo = await setupRepo();
    await repo.stageVulnerable();

    const provider = stub();
    const { io } = capture();
    const edited: string[] = [];
    const { ask } = scriptedAsk(['edit', 'apply']);

    const code = await runPatchCommand({
      cwd: repo.dir,
      environment: environmentWithKey(),
      client: provider.client,
      ask,
      // The real editor is never opened; what the test checks is that the
      // command threads the developer's text through to the file on disk.
      edit: async (text) => {
        edited.push(text);
        return { ok: true, text: text.replace('", [userId]', '", [userId] /* reviewed */') };
      },
      ...io,
    });

    // The repaired diff is what was handed over: no `@@ -3,5 +3,5 @@` (the
    // model's counting) and a file header it never wrote.
    expect(edited[0]).toContain('--- a/server/routes/users.js');
    expect(edited[0]).toContain('@@ -3,5 +3,4 @@');

    // And the developer's version is what landed — not the model's, and not a
    // re-analysis of it.
    const after = await repo.read(TARGET);
    expect(after).toContain('[userId] /* reviewed */');
    expect(after).not.toContain('" + userId');
    expect(code).toBe(EXIT.OK);
  });

  it('reviews patches saved in the report when --from-report is used', async () => {
    const repo = await setupRepo();
    await repo.stageVulnerable();

    // A scan, exactly as the hook runs one. This is what writes the report the
    // developer comes back to — so this test covers FR-12's write as well.
    const provider = stub();
    const scanned = capture();
    const scan = await scanDiff({
      diff: await repo.stagedDiff(),
      repoRoot: repo.dir,
      environment: environmentWithKey(),
      client: provider.client,
      ...scanned.io,
    });
    expect(scan.analyses).toHaveLength(1);
    expect(scanned.out()).toBeDefined();

    // Nothing has been applied yet: the report holds the suggestion, and the
    // file is still vulnerable.
    expect(await repo.read(TARGET)).toBe(VULNERABLE);

    const second = capture();
    const { ask } = scriptedAsk(['apply']);
    const code = await runPatchCommand({
      cwd: repo.dir,
      fromReport: true,
      ask,
      // A provider that would throw if it were used: --from-report must not
      // call the API, which is the whole point of the flag.
      client: {
        model: 'must-not-be-called',
        complete: async () => {
          throw new LlmError('the provider was called despite --from-report', 'transport');
        },
      },
      ...second.io,
    });

    expect(await repo.read(TARGET)).toContain(FIXED_QUERY_LINE);
    expect(await repo.stagedDiff()).toContain(FIXED_QUERY_LINE);
    expect(second.out()).toContain('from .codeguard/report.json');
    expect(second.err()).not.toContain('must-not-be-called');
    // No re-scan on this path, so no gate verdict is claimed — the message
    // points at the command that owns the verdict instead.
    expect(second.out()).toContain('Run `codeguard scan` to check the staged diff');
    expect(code).toBe(EXIT.OK);
  });

  /**
   * The live failure this path was built for: triage flags a real issue, deep
   * analysis answers with `file: ""`, and the pipeline discards that answer —
   * correctly, because it names a file nobody showed it. The finding survives,
   * so the commit is still blocked, but there is no patch to offer.
   *
   * Before, that finding simply vanished from the review: the command said "no
   * suggested patches to review" about a diff it had just called Critical, and a
   * developer had no way to tell that from a broken run. Now it is named, with
   * the reason, and still offered — [e] is how they fix it by hand.
   */
  it('names the finding and the reason when deep analysis was discarded', async () => {
    const repo = await setupRepo();
    await repo.stageVulnerable();

    const { io, out } = capture();
    const { ask, asked, questions } = scriptedAsk(['skip']);

    const code = await runPatchCommand({
      cwd: repo.dir,
      environment: environmentWithKey(),
      client: {
        model: 'stub-model',
        complete: async (request) =>
          // The exact shape the live provider produced: a real finding, a real
          // explanation, and an empty file name that makes the answer unusable.
          request.reasoning
            ? JSON.stringify({
                file: '',
                line_range: [6, 6],
                severity: 'Critical',
                category: 'sql_injection',
                explanation: 'The id parameter is concatenated straight into the SQL text.',
                suggested_patch: MODEL_PATCH,
                confidence: 'high',
              })
            : triageAnswer(true),
      },
      ask,
      ...io,
    });

    // 1. The developer is told, in the plural, before any prompt appears.
    expect(out()).toContain('1 finding came back with no patch');
    expect(out()).toContain('server/routes/users.js:6');
    expect(out()).toContain('deep analysis did not produce a patch');
    // 2. And NOT told there was nothing to review, which is what made the old
    //    behaviour indistinguishable from a clean scan.
    expect(out()).not.toContain('no suggested patches to review');

    // 3. The finding is still put in front of the developer, minus [a]pply —
    //    there is no patch to apply — with the reason attached to the question.
    expect(asked()).toBe(1);
    expect(questions()[0]?.canApply).toBe(false);
    expect(questions()[0]?.candidate.reason).toContain('deep analysis did not produce a patch');
    expect(questions()[0]?.candidate.reason).not.toContain('no hunk header');

    // 4. Nothing was written, and the commit is still blocked: "no patch" was
    //    never allowed to mean "no problem".
    expect(await repo.read(TARGET)).toBe(VULNERABLE);
    expect(code).toBe(EXIT.BLOCKED);
  });

  /**
   * The other way an analysis arrives with no patch: the model's patch quoted a
   * value CodeGuard had redacted before sending. The engine withholds the text
   * rather than putting `«REDACTED:…»` in the report for someone to copy into
   * their file — and the sentence explaining that is what the review shows.
   */
  it('says why a withheld patch cannot be applied, instead of dropping it', async () => {
    const repo = await setupRepo();
    await repo.stageVulnerable();

    const withheldPatch = [
      '@@ -3,5 +3,4 @@',
      " router.get('/users/:id', (req, res) => {",
      '   const userId = req.params.id;',
      '-  const sql = "SELECT id, email FROM users WHERE id = " + userId;',
      '-  db.query(sql, (err, rows) => res.json(rows));',
      `+  const sql = "SELECT id, email FROM users WHERE id = ?"; // key «REDACTED:aws-access-key»`,
      ' });',
    ].join('\n');

    const { io, out } = capture();
    const { ask, questions } = scriptedAsk(['skip']);

    const code = await runPatchCommand({
      cwd: repo.dir,
      environment: environmentWithKey(),
      client: {
        model: 'stub-model',
        complete: async (request) =>
          request.reasoning
            ? JSON.stringify({
                file: TARGET,
                line_range: [6, 6],
                severity: 'Critical',
                category: 'sql_injection',
                explanation: 'The id parameter is concatenated straight into the SQL text.',
                suggested_patch: withheldPatch,
                confidence: 'high',
              })
            : triageAnswer(true),
      },
      ask,
      ...io,
    });

    expect(out()).toContain('1 finding came back with no patch');
    expect(out()).toContain('quotes a value that CodeGuard redacted');
    expect(questions()[0]?.canApply).toBe(false);
    expect(questions()[0]?.candidate.reason).toContain('redacted');
    // The placeholder itself is never shown: it belongs to no real source, and
    // the one place it could do damage is a file the developer is about to commit.
    expect(out()).not.toContain('«REDACTED');
    expect(await repo.read(TARGET)).toBe(VULNERABLE);
    expect(code).toBe(EXIT.BLOCKED);
  });

  it('says there is nothing to apply in Local Mode, and does not prompt', async () => {
    const repo = await setupRepo();
    await repo.stageVulnerable();

    const { io, out } = capture();
    const { ask, asked } = scriptedAsk([]);

    const code = await runPatchCommand({ cwd: repo.dir, local: true, ask, ...io });

    expect(asked()).toBe(0);
    expect(out()).toContain('Local Mode is detection-only');
    expect(out()).toContain('DEEPSEEK_API_KEY');
    // The findings still block: "nothing to patch" is not "nothing to fix".
    expect(code).toBe(EXIT.BLOCKED);
  });

  it('refuses to run without a terminal rather than hanging in CI', async () => {
    // No `ask` injected, and Jest's stdin is not a TTY — which is exactly the
    // situation in CI, under a pipe, or inside an editor integration. inquirer
    // would otherwise wait forever for an answer nobody can give.
    const repo = await setupRepo();
    const { io, err } = capture();

    const code = await runPatchCommand({ cwd: repo.dir, ...io });

    expect(code).toBe(EXIT.ERROR);
    expect(err()).toContain('needs a terminal');
  });

  it('reports --from-report as an error when no report has been written', async () => {
    const repo = await setupRepo();
    const { io, err } = capture();

    const code = await runPatchCommand({ cwd: repo.dir, fromReport: true, ask: scriptedAsk([]).ask, ...io });

    expect(code).toBe(EXIT.ERROR);
    expect(err()).toContain('there is no .codeguard/report.json');
  });

  it('reports an error outside a repository instead of guessing', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'codeguard-not-a-repo-'));
    cleanup.push(dir);

    const { io, err } = capture();
    const code = await runPatchCommand({ cwd: dir, ask: scriptedAsk([]).ask, ...io });

    expect(code).toBe(EXIT.ERROR);
    expect(err()).toContain('not inside a Git repository');
  });
});
