import { describe, expect, it } from '@jest/globals';

import { runLocalScan, type Rule } from '../index';
import { diffForFixture, fixtureLines, newFileDiff, readFixture } from './helpers';

describe('runLocalScan against fixtures', () => {
  it('flags exactly the three vulnerable queries in the SQL fixture', async () => {
    const content = readFixture('sql-injection.js');
    const findings = await runLocalScan(diffForFixture('sql-injection.js', 'server/routes/users.js'));

    expect(findings.map((finding) => finding.ruleId).sort()).toEqual([
      'sql-string-concatenation',
      'sql-string-concatenation',
      'sql-template-interpolation',
    ]);

    // The reported line numbers must point at the vulnerable lines themselves,
    // not merely be plausible numbers.
    const lines = fixtureLines(content);
    const concatenated = findings.filter((f) => f.ruleId === 'sql-string-concatenation');
    const interpolated = findings.find((f) => f.ruleId === 'sql-template-interpolation')!;

    expect(lines[concatenated[0]!.line - 1]).toContain('+ userId');
    expect(lines[interpolated.line - 1]).toContain('${status}');
    // The regression case, asserted at the fixture level too: a concatenated
    // value that is QUOTED. This line was in no fixture until the character
    // class that could not see it was fixed.
    expect(lines[concatenated[1]!.line - 1]).toContain(`'" + name + "'`);
    expect(findings.every((finding) => finding.file === 'server/routes/users.js')).toBe(true);
  });

  it('flags all four unsafe calls in the C fixture', async () => {
    const findings = await runLocalScan(diffForFixture('unsafe-c.c', 'src/main.c'));

    expect(findings.map((finding) => finding.ruleId).sort()).toEqual([
      'command-injection-system',
      'unsafe-c-gets',
      'unsafe-c-sprintf',
      'unsafe-c-strcpy',
    ]);
  });

  it('flags the three real credentials in the Python fixture', async () => {
    const findings = await runLocalScan(diffForFixture('hardcoded-secret.py', 'app/settings.py'));

    // Two assignment matches plus the AWS key id. The four placeholder lines are
    // suppressed by the rule's refine() guard, so they must not appear.
    expect(findings.map((finding) => finding.ruleId).sort()).toEqual([
      'hardcoded-secret-assignment',
      'hardcoded-secret-assignment',
      'hardcoded-secret-aws-key',
    ]);
  });

  it('finds nothing in the clean JavaScript fixture', async () => {
    expect(await runLocalScan(diffForFixture('clean.js', 'src/clean.js'))).toEqual([]);
  });

  it('finds nothing in the clean C fixture', async () => {
    expect(await runLocalScan(diffForFixture('clean.c', 'src/clean.c'))).toEqual([]);
  });

  it.each(['sql-injection.js', 'unsafe-c.c', 'hardcoded-secret.py'])(
    'anchors every finding in %s to a real, non-comment source line',
    async (fixtureName) => {
      const content = readFixture(fixtureName);
      const lines = fixtureLines(content);
      const findings = await runLocalScan(newFileDiff(`src/${fixtureName}`, content));

      expect(findings.length).toBeGreaterThan(0);

      for (const finding of findings) {
        expect(finding.line).toBeGreaterThanOrEqual(1);
        expect(finding.line).toBeLessThanOrEqual(lines.length);

        // A finding pointing at a blank line or a comment would mean the line
        // numbering had drifted.
        const source = (lines[finding.line - 1] ?? '').trim();
        expect(source).not.toBe('');
        expect(source.startsWith('//')).toBe(false);
        expect(source.startsWith('#')).toBe(false);
        expect(source.startsWith('/*')).toBe(false);
      }
    },
  );
});

describe('runLocalScan scope of analysis', () => {
  it('ignores deleted and unchanged context lines', async () => {
    // Both lines below contain a real-looking secret. One is being DELETED and
    // one is only CONTEXT — neither is introduced by this commit, so neither
    // should be reported.
    const diff = [
      'diff --git a/app.py b/app.py',
      'index 1111111..2222222 100644',
      '--- a/app.py',
      '+++ b/app.py',
      '@@ -1,2 +1,1 @@',
      '-PASSWORD = "deleted_real_secret_value"',
      ' PASSWORD = "context_real_secret_value"',
      '',
    ].join('\n');

    expect(await runLocalScan(diff)).toEqual([]);
  });

  it('returns findings in diff order: file, then line, then rule', async () => {
    const diff = [
      newFileDiff('a/first.py', 'PASSWORD = "first_secret_value"'),
      newFileDiff('b/second.py', 'PASSWORD = "second_secret_value"\nAUTH_TOKEN = "third_secret_value"'),
    ].join('');

    const findings = await runLocalScan(diff);
    expect(findings.map((finding) => `${finding.file}:${finding.line}`)).toEqual([
      'a/first.py:1',
      'b/second.py:1',
      'b/second.py:2',
    ]);
  });

  it('carries each rule’s severity through to the finding', async () => {
    const findings = await runLocalScan(
      newFileDiff('src/main.c', 'gets(buf);\nstrcpy(dest, src);\nsystem(cmd);'),
    );

    const severityOf = (ruleId: string): string =>
      findings.find((finding) => finding.ruleId === ruleId)!.severity;

    expect(severityOf('unsafe-c-gets')).toBe('Critical');
    expect(severityOf('command-injection-system')).toBe('Critical');
    expect(severityOf('unsafe-c-strcpy')).toBe('High');
  });

  it('uses a caller-supplied rule set instead of the built-in one', async () => {
    // This is the seam FR-13 would plug into, so it is worth pinning down that
    // passing rules REPLACES the defaults rather than merging with them.
    const customRules: Rule[] = [
      {
        id: 'no-console-log',
        category: 'other',
        severity: 'Low',
        message: 'Remove console.log() before committing.',
        pattern: /\bconsole\.log\s*\(/,
      },
    ];

    const code = 'console.log("debug");';
    expect(await runLocalScan(newFileDiff('src/a.js', code))).toEqual([]);

    const findings = await runLocalScan(newFileDiff('src/a.js', code), { rules: customRules });
    expect(findings.map((finding) => finding.ruleId)).toEqual(['no-console-log']);
    expect(findings[0]!.severity).toBe('Low');
  });
});
