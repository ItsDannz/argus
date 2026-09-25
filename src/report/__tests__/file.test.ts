/**
 * The local scan report (FR-12), read and written.
 *
 * The interesting behaviour here is not the happy path — it is that READ is
 * strict and WRITE never throws. `patch --from-report` decides what gets written
 * to the developer's files from this data, so a report it cannot vouch for has
 * to be refused with a reason; and the pre-commit gate must not block a commit
 * because it could not write a cache file.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from '@jest/globals';

import type { DeepAnalysis } from '../../engine/remote';
import type { Finding } from '../../engine/findings';
import {
  buildReport,
  ensureReportIgnored,
  readReport,
  reportPath,
  REPORT_FILENAME,
  REPORT_VERSION,
  writeReport,
  type ReportInput,
} from '../file';

const cleanup: string[] = [];

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function scratch(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'codeguard-report-'));
  cleanup.push(dir);
  return dir;
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    file: 'server/routes/users.js',
    line: 11,
    severity: 'Critical',
    category: 'sql_injection',
    ruleId: 'sql-string-concatenation',
    message: 'User input is concatenated into the query string.',
    ...over,
  };
}

function analysis(over: Partial<DeepAnalysis> = {}): DeepAnalysis {
  return {
    file: 'server/routes/users.js',
    line: 11,
    severity: 'Critical',
    category: 'sql_injection',
    explanation: 'The id parameter is concatenated straight into the SQL text.',
    patch: '--- a/server/routes/users.js\n+++ b/server/routes/users.js\n@@ -9,3 +9,3 @@\n',
    confidence: 'high',
    withheld: null,
    redacted: false,
    ...over,
  };
}

function input(over: Partial<ReportInput> = {}): ReportInput {
  return {
    engine: 'remote',
    findings: [finding()],
    dismissed: [],
    analyses: [analysis()],
    notes: ['1 secret-like value was redacted from the diff'],
    ...over,
  };
}

describe('buildReport', () => {
  it('stamps the version and the moment it was built', () => {
    const report = buildReport(input(), new Date('2026-09-24T10:15:00.000Z'));

    expect(report.version).toBe(REPORT_VERSION);
    expect(report.generatedAt).toBe('2026-09-24T10:15:00.000Z');
  });

  it('copies the arrays rather than aliasing the caller`s', () => {
    // A report that shares an array with the scan result would keep changing
    // after the scan finished, and the file would describe something that never
    // happened.
    const findings = [finding()];
    const report = buildReport(input({ findings }));

    findings.push(finding({ line: 99 }));

    expect(report.findings).toHaveLength(1);
  });
});

describe('writeReport and readReport', () => {
  it('writes .codeguard/report.json, creating the directory', async () => {
    const repo = await scratch();
    const written = await writeReport(repo, input());

    expect(written.problem).toBeNull();
    expect(written.path).toBe(`.codeguard/${REPORT_FILENAME}`);

    // `.codeguard/` is ignored by Git, so it will not exist in a fresh clone.
    const onDisk = JSON.parse(await readFile(reportPath(repo), 'utf8')) as { version: number };
    expect(onDisk.version).toBe(REPORT_VERSION);
  });

  it('reads back everything a later run needs', async () => {
    const repo = await scratch();
    await writeReport(repo, input());

    const loaded = await readReport(repo);
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;

    expect(loaded.report.engine).toBe('remote');
    expect(loaded.report.findings).toEqual([finding()]);
    expect(loaded.report.analyses).toEqual([analysis()]);
    expect(loaded.report.notes).toEqual(['1 secret-like value was redacted from the diff']);
  });

  it('says what to do when there is no report yet', async () => {
    const loaded = await readReport(await scratch());

    expect(loaded.ok).toBe(false);
    expect(loaded.ok ? '' : loaded.reason).toContain('there is no .codeguard/report.json');
    expect(loaded.ok ? '' : loaded.reason).toContain('codeguard scan');
  });

  it('refuses a report written by a different version', async () => {
    const repo = await scratch();
    await mkdir(path.dirname(reportPath(repo)), { recursive: true });
    await writeFile(
      reportPath(repo),
      JSON.stringify({ ...buildReport(input()), version: REPORT_VERSION + 1 }),
      'utf8',
    );

    const loaded = await readReport(repo);
    expect(loaded.ok).toBe(false);
    expect(loaded.ok ? '' : loaded.reason).toContain('different version of CodeGuard');
  });

  it('refuses a truncated file instead of producing findings with missing fields', async () => {
    const repo = await scratch();
    await mkdir(path.dirname(reportPath(repo)), { recursive: true });
    await writeFile(reportPath(repo), '{ "version": 1, "findings": [', 'utf8');

    const loaded = await readReport(repo);
    expect(loaded.ok).toBe(false);
    expect(loaded.ok ? '' : loaded.reason).toContain('not valid JSON');
  });

  it('refuses a report with no findings or analyses array', async () => {
    const repo = await scratch();
    await mkdir(path.dirname(reportPath(repo)), { recursive: true });
    await writeFile(reportPath(repo), JSON.stringify({ version: REPORT_VERSION }), 'utf8');

    const loaded = await readReport(repo);
    expect(loaded.ok).toBe(false);
    expect(loaded.ok ? '' : loaded.reason).toContain('missing its findings or analyses');
  });

  it('tolerates a report missing its optional halves', async () => {
    // Written by a build that had no dismissed findings and no notes, or edited
    // by hand down to the parts the developer cares about.
    const repo = await scratch();
    await mkdir(path.dirname(reportPath(repo)), { recursive: true });
    await writeFile(
      reportPath(repo),
      JSON.stringify({ version: REPORT_VERSION, findings: [], analyses: [] }),
      'utf8',
    );

    const loaded = await readReport(repo);
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    expect(loaded.report.dismissed).toEqual([]);
    expect(loaded.report.notes).toEqual([]);
    expect(loaded.report.generatedAt).toBe('');
  });
});

describe('ensureReportIgnored', () => {
  it('adds the entry to a .gitignore that lacks it', async () => {
    const repo = await scratch();
    await writeFile(path.join(repo, '.gitignore'), 'node_modules/\n*.log\n', 'utf8');

    const result = await ensureReportIgnored(repo);

    expect(result.changed).toBe(true);
    expect(result.problem).toBeNull();
    const contents = await readFile(path.join(repo, '.gitignore'), 'utf8');
    // Appended, not rewritten: the developer's own rules are still there, in
    // order, and the file still ends in exactly one newline.
    expect(contents).toBe('node_modules/\n*.log\n.codeguard/\n');
  });

  it('creates the file when there is none', async () => {
    const repo = await scratch();

    const result = await ensureReportIgnored(repo);

    expect(result.changed).toBe(true);
    expect(await readFile(path.join(repo, '.gitignore'), 'utf8')).toBe('.codeguard/\n');
  });

  it('adds a separating newline to a file that does not end in one', async () => {
    // Without this the entry would be glued to the last rule and would ignore
    // something nobody asked it to.
    const repo = await scratch();
    await writeFile(path.join(repo, '.gitignore'), 'node_modules/', 'utf8');

    await ensureReportIgnored(repo);

    expect(await readFile(path.join(repo, '.gitignore'), 'utf8')).toBe('node_modules/\n.codeguard/\n');
  });

  it('leaves a .gitignore that already covers the directory alone', async () => {
    const repo = await scratch();
    const before = '# build output\n.codeguard\n';
    await writeFile(path.join(repo, '.gitignore'), before, 'utf8');

    const result = await ensureReportIgnored(repo);

    expect(result.changed).toBe(false);
    expect(result.problem).toBeNull();
    // Byte-identical: re-running `install` must not keep appending.
    expect(await readFile(path.join(repo, '.gitignore'), 'utf8')).toBe(before);
  });

  it('does not mistake a rule that merely contains the name for a match', async () => {
    // `.codeguardrc.json` is a config file this project expects to be committed,
    // and `dist/.codeguard/` is a different directory. Only whole-line matches
    // count, and neither of these is one.
    const repo = await scratch();
    await writeFile(path.join(repo, '.gitignore'), '.codeguardrc.json\ndist/.codeguard/\n', 'utf8');

    const result = await ensureReportIgnored(repo);

    expect(result.changed).toBe(true);
    expect(await readFile(path.join(repo, '.gitignore'), 'utf8')).toContain('\n.codeguard/\n');
  });

  it('reports rather than throws when the .gitignore cannot be read', async () => {
    // `.gitignore` as a DIRECTORY: readable as a path, not as a file. An install
    // that put the hook on disk must not be reported as failed because of this.
    const repo = await scratch();
    await mkdir(path.join(repo, '.gitignore'));

    const result = await ensureReportIgnored(repo);

    expect(result.changed).toBe(false);
    expect(result.problem).toContain('could not read .gitignore');
  });
});

describe('writeReport — failures are reported, never thrown', () => {
  it('reports a problem instead of throwing when the path is unusable', async () => {
    // `.codeguard` exists as a FILE, so the directory cannot be created. This is
    // the shape any unwritable path takes, and the caller is a pre-commit hook:
    // a scan must not die because a cache file could not be written.
    const repo = await scratch();
    await writeFile(path.join(repo, '.codeguard'), 'not a directory\n', 'utf8');

    const written = await writeReport(repo, input());

    expect(written.path).toBeNull();
    expect(written.problem).toContain('could not write .codeguard/report.json');
  });

  it('reports a problem for a path the filesystem refuses outright', async () => {
    // A NUL byte can never be part of a path. It stands in for "the write threw
    // something other than a permissions error": the point is that writeReport
    // converts it into a reason rather than letting it reach the caller.
    const written = await writeReport(path.join(tmpdir(), 'codeguard\0bad'), input());

    expect(written.path).toBeNull();
    expect(written.problem).not.toBeNull();
  });
});
