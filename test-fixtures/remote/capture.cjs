/**
 * Records what the live provider actually answers, so the Remote Mode tests can
 * be run against real output without a network, a key, or a bill.
 *
 *   set -a; . ./.env; set +a
 *   node test-fixtures/remote/capture.cjs
 *
 * It writes, into this directory:
 *
 *   diff.patch    the exact staged diff the answers were given
 *   triage.json   the Stage-1 answer, verbatim
 *   deep.json     the Stage-2 answers, verbatim, in the order they were asked
 *
 * The diff is recorded because the answers only mean anything relative to it: a
 * triage answer names line ranges, and a Stage-2 answer names a file and a hunk.
 * `fixtures.e2e.test.ts` rebuilds the same diff and refuses to replay against a
 * different one, so editing a fixture file fails the test with "the recorded
 * answers were captured against a different diff" rather than with a mapping
 * error three layers down.
 *
 * Nothing here prints the diff or the answers: they are written to files, and
 * this script's stdout stays small enough to read.
 */

const { execFileSync } = require('node:child_process');
const { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');

const { createDeepSeekClient } = require('../../dist/engine/remote/client.js');
const { runRemoteScan } = require('../../dist/engine/remote/index.js');
const { runLocalScan } = require('../../dist/engine/local/index.js');

const HERE = __dirname;
const MINI_REPO = path.join(HERE, '..', 'mini-repo');

/** The files the recorded answers cover. Both, because the pair proves the
 *  redaction pass end to end: one is a SQL injection, the other a credential. */
const COVERED = ['src/routes/users.js', 'src/config.js'];

function materialise() {
  const dir = mkdtempSync(path.join(tmpdir(), 'codeguard-capture-'));
  const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: 'pipe' });
  git('init', '-q', '.');
  git('config', 'user.email', 'capture@example.com');
  git('config', 'user.name', 'CodeGuard capture');
  git('config', 'core.autocrlf', 'false');

  for (const relative of COVERED) {
    const target = path.join(dir, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(path.join(MINI_REPO, relative), target);
  }
  git('add', ...COVERED);
  return dir;
}

(async () => {
  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (apiKey === undefined || apiKey === '') {
    console.error('DEEPSEEK_API_KEY is not set — source .env before capturing.');
    process.exit(1);
  }

  const root = materialise();
  const diff = execFileSync('git', ['diff', '--cached'], { cwd: root, encoding: 'utf8' });
  const baseline = await runLocalScan(diff, {});

  const base = createDeepSeekClient({ apiKey });
  const triage = [];
  const deep = [];
  const client = {
    model: base.model,
    complete: async (request, signal) => {
      const answer = await base.complete(request, signal);
      (request.reasoning ? deep : triage).push(answer);
      return answer;
    },
  };

  try {
    const outcome = await runRemoteScan({
      diff,
      credentials: { apiKey, model: base.model },
      remote: { maxDeepAnalysisHunks: 5, timeoutMs: 120000, maxDiffBytes: 200000 },
      baseline,
      onProgress: (message) => process.stderr.write(`${message}\n`),
      client,
    });

    writeFileSync(path.join(HERE, 'diff.patch'), diff, 'utf8');
    writeFileSync(path.join(HERE, 'triage.json'), `${JSON.stringify(triage, null, 2)}\n`, 'utf8');
    writeFileSync(path.join(HERE, 'deep.json'), `${JSON.stringify(deep, null, 2)}\n`, 'utf8');

    console.log(`model:        ${base.model}`);
    console.log(`triage bytes: ${triage.join('').length}`);
    console.log(`deep answers: ${deep.length}`);
    console.log(`findings:     ${outcome.findings.length}`);
    console.log(`analyses:     ${outcome.analyses.length} (patches: ${outcome.analyses.filter((a) => a.patch !== '').length})`);
    console.log(`dismissed:    ${outcome.dismissed.length}`);
    for (const note of outcome.notes) console.log(`note: ${note}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
})();
