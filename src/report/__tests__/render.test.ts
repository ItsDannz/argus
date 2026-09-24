import { describe, expect, it } from '@jest/globals';

import type { Severity } from '../../prompts/security-agent-prompts';
import type { LocalFinding } from '../../engine/local/types';
import { evaluateThreshold } from '../../engine/threshold';
import {
  renderConfigProblems,
  renderFindings,
  renderFindingsReport,
  renderVerdict,
} from '../render';

function finding(over: Partial<LocalFinding> = {}): LocalFinding {
  return {
    file: 'src/db.js',
    line: 12,
    ruleId: 'sql-string-concatenation',
    severity: 'Critical',
    message: 'SQL assembled with string concatenation.',
    ...over,
  };
}

const ESCAPE = '\u001b[';

describe('renderFindings', () => {
  it('returns nothing at all when there are no findings', () => {
    expect(renderFindings([])).toBe('');
  });

  it('lays a row out as file, location, severity, rule id, then the message', () => {
    const output = renderFindings([finding()]);
    expect(output).toContain('  src/db.js');
    // Line number right-aligned in 5, severity left-aligned in 8 (the width of
    // "Critical"), then the rule id.
    expect(output).toContain('       12  Critical  sql-string-concatenation');
    expect(output).toContain('        SQL assembled with string concatenation.');
  });

  it('right-aligns line numbers so the severity column stays in one place', () => {
    const output = renderFindings([finding({ line: 7 }), finding({ line: 1234, severity: 'High' })]);
    expect(output).toContain('        7  Critical');
    expect(output).toContain('     1234  High    ');
  });

  it('groups findings by file, keeping diff order within a file', () => {
    const output = renderFindings([
      finding({ file: 'a.js', line: 1, ruleId: 'first' }),
      finding({ file: 'b.js', line: 2, ruleId: 'second' }),
      finding({ file: 'a.js', line: 3, ruleId: 'third' }),
    ]);

    expect(output.indexOf('  a.js')).toBeLessThan(output.indexOf('  b.js'));
    expect(output.indexOf('first')).toBeLessThan(output.indexOf('third'));
    // Two files, so two headers.
    expect(output.match(/^ {2}\S/gm)).toHaveLength(2);
  });

  it('wraps a long message and indents every wrapped line', () => {
    const message = Array.from({ length: 40 }, (_, index) => `word${index}`).join(' ');
    const output = renderFindings([finding({ message })]);

    // Drop the file header and the severity row; what remains is the wrapped
    // message, which must be indented on every line and — indent included —
    // inside the wrap width.
    const lines = output.split('\n').filter((line) => line !== '');
    expect(lines[1]).toContain('sql-string-concatenation');

    const messageLines = lines.slice(2);
    expect(messageLines.length).toBeGreaterThan(1);
    for (const line of messageLines) {
      expect(line.startsWith('        ')).toBe(true);
      expect(line.length).toBeLessThanOrEqual(76);
    }
  });

  it('emits a word longer than the wrap width whole rather than splitting it', () => {
    const longWord = 'x'.repeat(90);
    const output = renderFindings([finding({ message: `prefix ${longWord}` })]);
    expect(output).toContain(longWord);
  });

  it('emits no ANSI escapes by default', () => {
    expect(renderFindings([finding()])).not.toContain(ESCAPE);
  });

  it('emits ANSI escapes only when colour is requested', () => {
    const output = renderFindings([finding()], { useColor: true });
    expect(output).toContain(ESCAPE);
    expect(output).toContain('\u001b[31m'); // High and Critical both use red
    expect(output).toContain('\u001b[0m'); // and everything is reset
  });

  it('pads before painting, so colour never disturbs the column widths', () => {
    // padEnd counts the escape characters as content. Padding first and painting
    // second is what keeps the rule-id column aligned across severities.
    const plain = renderFindings([finding({ severity: 'Low' })]);
    const coloured = renderFindings([finding({ severity: 'Low' })], { useColor: true });
    expect(coloured.replace(/\u001b\[\d+m/g, '')).toBe(plain);
  });
});

describe('renderFindingsReport', () => {
  it('reports a clean scan in the singular-free way', () => {
    expect(renderFindingsReport([])).toContain('no issues found');
  });

  it('counts issues and files with correct pluralisation', () => {
    expect(renderFindingsReport([finding()])).toContain('1 issue in 1 file');
    expect(renderFindingsReport([finding(), finding({ ruleId: 'other' })])).toContain('2 issues in 1 file');
    expect(renderFindingsReport([finding(), finding({ file: 'b.js' })])).toContain('2 issues in 2 files');
  });

  it('names the engine, because the two modes give different guarantees', () => {
    expect(renderFindingsReport([])).toContain('local engine');
    expect(renderFindingsReport([finding()])).toContain('local engine');
  });
});

describe('renderVerdict', () => {
  const threshold = { blockOn: 'Critical' as Severity, warnOn: 'High' as Severity };

  it('states the threshold that fired and the override when the commit is blocked', () => {
    const decision = evaluateThreshold(
      [finding({ severity: 'Critical' }), finding({ severity: 'High' })],
      threshold,
    );
    const verdict = renderVerdict(decision, 'Critical', 'High');

    expect(verdict).toContain('Commit blocked');
    expect(verdict).toContain('at or above the block threshold "Critical"');
    expect(verdict).toContain('1 Critical, 1 High');
    // PRD §10.1 asks for the override to be documented rather than hidden.
    expect(verdict).toContain('git commit --no-verify');
  });

  it('distinguishes warnings from blocking', () => {
    const decision = evaluateThreshold([finding({ severity: 'High' })], threshold);
    const verdict = renderVerdict(decision, 'Critical', 'High');

    expect(verdict).toContain('Commit allowed');
    expect(verdict).not.toContain('Commit blocked');
    expect(verdict).toContain('at or above "High"');
  });

  it('says so when findings exist but none reach the warn threshold', () => {
    const decision = evaluateThreshold([finding({ severity: 'Low' })], threshold);
    const verdict = renderVerdict(decision, 'Critical', 'High');
    expect(verdict).toBe('No issues at or above the configured threshold.');
  });

  it('emits no ANSI escapes unless colour is requested', () => {
    const decision = evaluateThreshold([finding({ severity: 'Critical' })], threshold);
    expect(renderVerdict(decision, 'Critical', 'High')).not.toContain(ESCAPE);
    expect(renderVerdict(decision, 'Critical', 'High', { useColor: true })).toContain(ESCAPE);
  });
});

describe('renderConfigProblems', () => {
  it('returns nothing when the config is clean', () => {
    expect(renderConfigProblems([], '/repo/.codeguardrc.json')).toBe('');
  });

  it('names the file and lists each problem', () => {
    const output = renderConfigProblems(
      [
        { where: 'threshold.blockOn', message: 'must be one of ...' },
        { where: '', message: 'is not valid JSON' },
      ],
      '/repo/.codeguardrc.json',
    );
    expect(output).toContain('/repo/.codeguardrc.json');
    expect(output).toContain('- threshold.blockOn: must be one of ...');
    expect(output).toContain('- is not valid JSON');
  });

  it('copes with no known config path', () => {
    expect(renderConfigProblems([{ where: '', message: 'bad' }], null)).toContain(
      'problem in configuration',
    );
  });
});
