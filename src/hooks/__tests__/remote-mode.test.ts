/**
 * Mode selection as it reaches the hook, and the fallback (FR-3, PRD §6.3).
 *
 * The remote engine has its own tests; what is verified here is the INTEGRATION
 * — that the hook asks the right question, prints results under the right engine
 * label, and degrades in the right direction when the provider is unreachable.
 * The Phase 4 acceptance criterion is exactly that last one: "disconnecting
 * network / removing the API key falls back to Local Mode without crashing".
 *
 * The provider is stubbed and the environment injected throughout, so nothing
 * here can reach the network or depend on what happens to be exported in the
 * shell that runs the tests.
 */

import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, describe, expect, it } from '@jest/globals';

import { CONFIG_FILENAME } from '../../config/schema';
import type { Environment } from '../../engine/mode';
import { API_KEY_VAR } from '../../engine/mode';
import { diffForFixture } from '../../engine/local/__tests__/helpers';
import { LlmError, type LlmClient } from '../../engine/remote';
import type { LlmRequest } from '../../engine/remote/client';
import { EXIT } from '../../exit-codes';
import { scanDiff } from '../pre-commit';

const KEY = 'sk-live-9f2b7c41d8e35a60b4c7f1e2';
const REPO_ROOT = '/nowhere/scratch-repo';

/**
 * A SQL injection the LOCAL rules also detect, so a fallback is observable.
 *
 * The quotation inside the string is deliberate. This fixture used to avoid it
 * because `sql-string-concatenation` could not match a query containing an
 * apostrophe — the rule's character class excluded both quote characters, so
 * the string looked unterminated and the injection went unreported. That gap is
 * fixed, and this fixture now uses the shape real code uses rather than the one
 * the rule happened to accept. If it ever stops being detected, the fallback
 * test below fails, which is the point.
 */
const SQLI_DIFF = [
  'diff --git a/src/db.js b/src/db.js',
  'new file mode 100644',
  'index 0000000..1111111',
  '--- /dev/null',
  '+++ b/src/db.js',
  '@@ -0,0 +1,3 @@',
  '+function findUser(db, name) {',
  `+  const sql = "SELECT * FROM users WHERE name = '" + name + "'";`,
  '+  return db.query(sql);',
  '+}',
  '',
].join('\n');

/** A change the regex rules cannot see at all. */
const CLEAN_DIFF = [
  'diff --git a/src/math.js b/src/math.js',
  'index 1111111..2222222 100644',
  '--- a/src/math.js',
  '+++ b/src/math.js',
  '@@ -1,2 +1,3 @@',
  ' const add = (a, b) => a + b;',
  '+const sub = (a, b) => a - b;',
  ' const mul = (a, b) => a * b;',
  '',
].join('\n');

function environmentWith(env: NodeJS.ProcessEnv): Environment {
  return { env, envFile: null, fromFile: [] };
}

const WITH_KEY = environmentWith({ [API_KEY_VAR]: KEY });
const WITHOUT_KEY = environmentWith({});

const TRIAGE_HIT = JSON.stringify({
  findings: [
    {
      file: 'src/math.js',
      line_range: [2, 2],
      severity: 'Critical',
      category: 'logic_bug',
      summary: 'subtraction changes existing behaviour',
    },
  ],
});

/** A diff carrying a live-looking credential, to exercise the redaction note. */
const SECRET_DIFF = [
  'diff --git a/src/config.js b/src/config.js',
  'new file mode 100644',
  'index 0000000..3333333',
  '--- /dev/null',
  '+++ b/src/config.js',
  '@@ -0,0 +1,1 @@',
  '+const API_KEY = "sk-live-9f2b7c41d8e35a60b4c7f1e2";',
  '',
].join('\n');

const PATCH = JSON.stringify({
  file: 'src/math.js',
  line_range: [2, 2],
  severity: 'Critical',
  category: 'logic_bug',
  explanation: 'This looks like it should be addition.',
  suggested_patch: '--- a/src/math.js\n+++ b/src/math.js\n@@ -1,3 +1,3 @@\n-const sub = (a, b) => a - b;\n+const sub = (a, b) => a + b;',
  confidence: 'high',
});

/** Records what it was asked, and answers from canned text. */
function stubClient(answers: { triage: string | Error; patch?: string | Error }): LlmClient {
  const requests: LlmRequest[] = [];
  return {
    model: 'stub-model',
    complete: async (request: LlmRequest): Promise<string> => {
      requests.push(request);
      if (request.system.includes('triage engine')) {
        if (answers.triage instanceof Error) throw answers.triage;
        return answers.triage;
      }
      const patch = answers.patch ?? PATCH;
      if (patch instanceof Error) throw patch;
      return patch;
    },
  };
}

/** Captures what the scan wrote, so the report text can be asserted on. */
function capture(): { io: { write: (t: string) => void; writeError: (t: string) => void }; out: () => string; err: () => string } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    io: { write: (text) => void stdout.push(text), writeError: (text) => void stderr.push(text) },
    out: () => stdout.join(''),
    err: () => stderr.join(''),
  };
}

const cleanup: string[] = [];

afterAll(async () => {
  await Promise.all(cleanup.map((dir) => rm(dir, { recursive: true, force: true })));
});

/**
 * A real directory holding a `.codeguardrc.json`.
 *
 * Real, unlike {@link REPO_ROOT}, because the config is what is under test here
 * and `loadConfig` reads it from disk — a fabricated path would exercise the
 * no-config branch instead, which is the one case this suite is not about.
 */
async function repoWithConfig(config: unknown): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'codeguard-mode-'));
  cleanup.push(dir);
  await writeFile(path.join(dir, CONFIG_FILENAME), JSON.stringify(config), 'utf8');
  return dir;
}

/**
 * A client that counts how often it was asked anything.
 *
 * The count, not the answer, is the assertion: "was the provider contacted at
 * all" is the question a mis-scoped mode setting gets wrong, and a stub that
 * merely returns text cannot tell the difference between being skipped and
 * being asked something it happened to answer.
 */
function countingClient(answer: string | Error): { client: LlmClient; calls: () => number } {
  let calls = 0;
  return {
    calls: () => calls,
    client: {
      model: 'counting-stub',
      complete: async (): Promise<string> => {
        calls += 1;
        if (answer instanceof Error) throw answer;
        return answer;
      },
    },
  };
}

describe('scanDiff — Local Mode is the keyless default', () => {
  it('runs the rule engine when no key is available', async () => {
    const { io, out } = capture();

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITHOUT_KEY,
      ...io,
    });

    expect(result.engine).toBe('local');
    expect(out()).toContain('local engine');
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.exitCode).toBe(EXIT.BLOCKED);
  });

  it('does not call a provider even when one is supplied', async () => {
    // `--local` is a promise that nothing leaves the machine, so it has to hold
    // even when credentials exist. Otherwise a developer reaching for the safe
    // option during an incident would silently transmit anyway.
    const { io, out } = capture();
    const client = stubClient({ triage: TRIAGE_HIT });

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      local: true,
      client,
      ...io,
    });

    expect(result.engine).toBe('local');
    expect(out()).toContain('local engine');
  });
});

/**
 * `remote.hookMode` reaches a scan the developer typed, not only the hook's.
 *
 * This is the wiring, which is a separate claim from the precedence itself
 * (`engine/__tests__/mode.test.ts` covers that): the setting lives in the config
 * file, `scanDiff` is what loads the config, and every entry point that scans
 * anything ends up there — the hook, `codeguard scan --staged`, and `codeguard
 * scan --diff`. A repository that committed `local-only` to keep its own commits
 * offline must not be one `node dist/cli.js scan` away from transmitting a diff.
 *
 * "No call was attempted" is asserted by counting an injected client's
 * invocations rather than by reading the mode branch, because the failure mode
 * this guards against — the setting not reaching the decision — looks perfectly
 * correct in the code that contains it.
 */
describe('scanDiff — remote.hookMode applies to a scan, not only to the hook', () => {
  it('does not contact the provider when the repository config says local-only', async () => {
    const dir = await repoWithConfig({ remote: { hookMode: 'local-only' } });
    const { io, out, err } = capture();
    const provider = countingClient(
      new LlmError('the provider was called by a scan that must not call it', 'transport'),
    );

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: dir,
      environment: WITH_KEY,
      client: provider.client,
      ...io,
    });

    expect(provider.calls()).toBe(0);
    expect(result.engine).toBe('local');
    expect(out()).toContain('local engine');
    expect(result.findings.length).toBeGreaterThan(0);
    // Nothing was attempted, so nothing failed. This is the configured default,
    // not the fallback, and the two must stay distinguishable in the output a
    // developer actually reads.
    expect(err()).not.toContain('DID NOT RUN');
  });

  it('does contact it from the same scan when the config says auto', async () => {
    // The control, and the reason the test above means anything: without it, a
    // scan that never reaches the provider for some unrelated reason — a stub the
    // pipeline cannot get to, a mode resolved before the client is consulted —
    // would let it pass while proving nothing. The config is the only difference
    // between the two.
    const dir = await repoWithConfig({ remote: { hookMode: 'auto' } });
    const { io } = capture();
    const provider = countingClient('{"findings":[]}');

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: dir,
      environment: WITH_KEY,
      client: provider.client,
      ...io,
    });

    expect(provider.calls()).toBeGreaterThan(0);
    expect(result.engine).toBe('remote');
    // And the rule engine still ran: the injection it detects keeps the commit
    // blocked even though triage reported nothing.
    expect(result.exitCode).toBe(EXIT.BLOCKED);
  });
});

describe('scanDiff — Remote Mode', () => {
  it('uses the AI engine when a key is present', async () => {
    const { io, out } = capture();

    const result = await scanDiff({
      diff: CLEAN_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: TRIAGE_HIT }),
      ...io,
    });

    expect(result.engine).toBe('remote');
    expect(out()).toContain('remote AI engine');
    // A finding the regex rules cannot reach at all — the reason Remote Mode
    // exists on top of Phase 2 rather than instead of it.
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe('logic_bug');
    expect(result.exitCode).toBe(EXIT.BLOCKED);
  });

  it('shows the suggested patch but states that nothing was applied', async () => {
    const { io, out } = capture();

    await scanDiff({
      diff: CLEAN_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: TRIAGE_HIT }),
      ...io,
    });

    const report = out();
    expect(report).toContain('confidence: high');
    expect(report).toContain('const sub = (a, b) => a - b;');
    // Phase 5 applies patches. Until then the report must not imply it already
    // did — a developer who believes a fix is in place will not make it.
    expect(report).toContain('nothing is changed yet');
  });

  it('reports findings deep analysis cleared, without counting them', async () => {
    const { io, out } = capture();
    const cleared = JSON.stringify({
      file: 'src/math.js',
      line_range: [2, 2],
      severity: 'Low',
      category: 'logic_bug',
      explanation: 'The subtraction is intentional.',
      suggested_patch: '',
      confidence: 'high',
    });

    const result = await scanDiff({
      diff: CLEAN_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: TRIAGE_HIT, patch: cleared }),
      ...io,
    });

    expect(result.findings).toHaveLength(0);
    expect(result.dismissed).toHaveLength(1);
    expect(result.exitCode).toBe(EXIT.OK);
    expect(out()).toContain('Cleared as false positives');
    expect(out()).toContain('no issues found');
  });

  it('puts operational notes on stderr, keeping stdout report-only', async () => {
    // The channel split matters more in Remote Mode than anywhere else, because
    // "we redacted two values and skipped three files" is exactly the sort of
    // line that would corrupt a report someone is parsing.
    const { io, out, err } = capture();

    await scanDiff({
      diff: SECRET_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: '{"findings":[]}' }),
      ...io,
    });

    expect(err()).toContain('Redacted');
    expect(out()).not.toContain('Redacted');

    // This assertion used to be `out()).toContain('no issues found')`. Stubbed
    // triage reports nothing, and Remote Mode previously had no way to see the
    // credential on that line at all — the rules that match it only ran when
    // Local Mode was selected. Now the rule engine's result is reconciled into
    // every remote scan, so the report carries the finding triage missed, and the
    // note explaining that stays on stderr with the rest of the operational
    // output. Both halves are what this test is about.
    expect(out()).toContain('CodeGuard (remote AI engine)');
    expect(out()).toContain('hardcoded-secret-assignment');
    expect(err()).toContain('the local rule engine did');
  });
});

describe('scanDiff — the fallback (PRD §6.3)', () => {
  it('falls back to Local Mode, loudly, when the provider is unreachable', async () => {
    // The Phase 4 acceptance criterion. A network failure must not crash the
    // hook and must not produce an empty report that reads as a clean scan.
    const { io, out, err } = capture();

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: new LlmError('could not reach https://api.deepseek.com') }),
      ...io,
    });

    expect(result.engine).toBe('local');
    expect(result.exitCode).toBe(EXIT.BLOCKED);
    // The local engine found the SQL injection, so the commit is still gated.
    expect(result.findings.length).toBeGreaterThan(0);
    expect(out()).toContain('local engine');

    const warnings = err();
    expect(warnings).toContain('Remote AI Mode failed');
    expect(warnings).toContain('DID NOT RUN');
    // The distinction that matters: the developer must not read this as "the AI
    // looked and found nothing".
    expect(warnings).toContain('does not mean the AI pass found nothing');
    expect(warnings).toContain('could not reach');
  });

  it('does not leak the API key into the fallback warning', async () => {
    // The provider is the one component that knows the key, and its error
    // message is the one string from it that reaches the terminal. FR-10.
    const { io, err } = capture();

    await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: new LlmError(`provider echoed back Bearer ${KEY}`) }),
      ...io,
    });

    // The stub deliberately bypasses the client's own redaction, so this
    // asserts the hook redacts independently. Two guards, because a key in a
    // CI log cannot be taken back.
    expect(err()).not.toContain(KEY);
    expect(err()).toContain('Remote AI Mode failed');
  });

  it('makes --remote without a key an error, not a quiet local scan', async () => {
    // Not a fallback, deliberately: the flag asked for an AI scan, and handing
    // back a regex scan would misrepresent what ran.
    const { io, out, err } = capture();

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITHOUT_KEY,
      remote: true,
      ...io,
    });

    expect(result.exitCode).toBe(EXIT.ERROR);
    expect(result.engine).toBe('local');
    expect(result.findings).toHaveLength(0);
    expect(out()).not.toContain('local engine');
    expect(err()).toContain(API_KEY_VAR);
    expect(err()).toContain('--remote');
  });

  it('rejects --local and --remote together', async () => {
    const { io, err } = capture();

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITHOUT_KEY,
      local: true,
      remote: true,
      ...io,
    });

    expect(result.exitCode).toBe(EXIT.ERROR);
    expect(err()).toContain('cannot be combined');
  });

  it('keeps a clean remote scan clean, and exits zero', async () => {
    // The other half of the fallback story: a remote scan that genuinely finds
    // nothing must exit zero rather than being treated as a failure to retry.
    const { io } = capture();

    const result = await scanDiff({
      diff: CLEAN_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: '{"findings":[]}' }),
      ...io,
    });

    expect(result.engine).toBe('remote');
    expect(result.findings).toHaveLength(0);
    expect(result.exitCode).toBe(EXIT.OK);
  });
});

/**
 * Which engine was configured must not change the outcome for code the rule
 * engine already has a confident answer about.
 *
 * The unit tests in engine/__tests__/reconcile.test.ts pin the policy; what
 * these pin is that the policy is actually wired into a scan — that both modes
 * are handed the same diff and come to the same conclusion about it. The fixture
 * is the real one, and the model's answers below are the shape the live provider
 * returned for it.
 */
describe('scanDiff — the two modes agree about the SQL fixture', () => {
  const FIXTURE_PATH = 'server/routes/users.js';
  const SQLI_FIXTURE_DIFF = diffForFixture('sql-injection.js', FIXTURE_PATH);

  /** What the live model actually answered: right file, right class, one tier low. */
  const TRIAGE_SQLI_HIGH = JSON.stringify({
    findings: [
      {
        file: FIXTURE_PATH,
        line_range: [11, 11],
        severity: 'High',
        category: 'sql_injection',
        summary: 'User input is concatenated into the query string.',
      },
    ],
  });

  const PATCH_SQLI_HIGH = JSON.stringify({
    file: FIXTURE_PATH,
    line_range: [11, 11],
    severity: 'High',
    category: 'sql_injection',
    explanation: 'The id parameter is concatenated straight into the SQL text.',
    suggested_patch:
      '--- a/server/routes/users.js\n+++ b/server/routes/users.js\n@@ -9,3 +9,3 @@\n' +
      '-  const sql = "SELECT id, email FROM users WHERE id = " + userId;\n' +
      '+  const sql = "SELECT id, email FROM users WHERE id = ?";\n',
    confidence: 'high',
  });

  it('blocks the commit the rule engine blocks, even rated lower by the model', async () => {
    // The defect this reconciliation exists for, at the level it was reported.
    // Before the floor, these two runs disagreed: Local Mode refused the commit
    // and Remote Mode warned and let it through — same fixture, same three
    // vulnerable queries, opposite outcomes, decided entirely by configuration.
    const localCapture = capture();
    const local = await scanDiff({
      diff: SQLI_FIXTURE_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITHOUT_KEY,
      ...localCapture.io,
    });

    const remoteCapture = capture();
    const remote = await scanDiff({
      diff: SQLI_FIXTURE_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: TRIAGE_SQLI_HIGH, patch: PATCH_SQLI_HIGH }),
      ...remoteCapture.io,
    });

    // Local Mode is the reference. Three queries, all Critical — the numbers
    // reported from the live run.
    expect(local.engine).toBe('local');
    expect(local.exitCode).toBe(EXIT.BLOCKED);
    expect(local.findings.map((finding) => finding.severity)).toEqual([
      'Critical',
      'Critical',
      'Critical',
    ]);

    // Remote Mode must reach the same verdict on the same code.
    expect(remote.engine).toBe('remote');
    expect(remote.exitCode).toBe(local.exitCode);
    expect(remote.findings).toHaveLength(3);
    expect(remote.findings.map((finding) => finding.severity)).toEqual([
      'Critical',
      'Critical',
      'Critical',
    ]);

    // And the same ROWS. The model reported line 11 only; lines 18 and 30 are
    // two more injections it never mentioned, and they are kept per line rather
    // than collapsed into the one finding the model did produce. Before that
    // change this scan reported a single row — while the same scan with deep
    // analysis failing and falling back to triage reported all three, which made
    // the report's shape depend on whether Stage 2 happened to succeed.
    expect(local.findings.map((finding) => finding.line)).toEqual([11, 18, 30]);
    expect(remote.findings.map((finding) => finding.line)).toEqual([11, 18, 30]);
    expect(remoteCapture.err()).toContain('raised to Critical');
    expect(remoteCapture.err()).toContain('2 other lines');
    // The report itself has to carry the raised severity, not just the exit
    // code: a developer reading "High" next to a blocked commit learns that the
    // gate is arbitrary.
    expect(remoteCapture.out()).toContain('Critical');
  });

  it('blocks it when triage reports nothing at all', async () => {
    // The same weakness from the other direction, and the more dangerous one:
    // the finding did not merely come back under-rated, it did not exist, so a
    // clean AI scan reported a clean diff for code Local Mode refuses.
    const localCapture = capture();
    const local = await scanDiff({
      diff: SQLI_FIXTURE_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITHOUT_KEY,
      ...localCapture.io,
    });

    const remoteCapture = capture();
    const remote = await scanDiff({
      diff: SQLI_FIXTURE_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: '{"findings":[]}' }),
      ...remoteCapture.io,
    });

    expect(remote.engine).toBe('remote');
    expect(remote.exitCode).toBe(EXIT.BLOCKED);
    expect(remote.findings).toEqual(local.findings);
    expect(remoteCapture.err()).toContain('the local rule engine did');
  });
});
