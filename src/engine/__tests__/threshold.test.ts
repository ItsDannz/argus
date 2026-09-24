import { describe, expect, it } from '@jest/globals';

import type { ThresholdConfig } from '../../config/schema';
import type { Severity } from '../../prompts/security-agent-prompts';
import type { LocalFinding } from '../local/types';
import { evaluateThreshold } from '../threshold';

function finding(severity: Severity, over: Partial<LocalFinding> = {}): LocalFinding {
  return {
    file: 'src/db.js',
    line: 1,
    ruleId: `rule-${severity.toLowerCase()}`,
    severity,
    message: `${severity} finding`,
    ...over,
  };
}

const DEFAULT: ThresholdConfig = { blockOn: 'Critical', warnOn: 'High' };

describe('evaluateThreshold', () => {
  it('returns empty lists and a null highest severity for no findings', () => {
    const decision = evaluateThreshold([], DEFAULT);
    expect(decision.blocking).toEqual([]);
    expect(decision.warned).toEqual([]);
    expect(decision.highest).toBeNull();
    expect(decision.counts).toEqual({ Critical: 0, High: 0, Medium: 0, Low: 0 });
  });

  it('blocks on a finding at the block threshold', () => {
    const decision = evaluateThreshold([finding('Critical')], DEFAULT);
    expect(decision.blocking).toHaveLength(1);
    expect(decision.warned).toEqual([]);
  });

  it('blocks on a finding above the block threshold', () => {
    const decision = evaluateThreshold([finding('Critical')], { blockOn: 'Medium', warnOn: 'Low' });
    expect(decision.blocking).toHaveLength(1);
  });

  it('warns on a finding between warnOn and blockOn', () => {
    const decision = evaluateThreshold([finding('High')], DEFAULT);
    expect(decision.blocking).toEqual([]);
    expect(decision.warned).toHaveLength(1);
  });

  it('neither blocks nor warns below both thresholds', () => {
    const decision = evaluateThreshold([finding('Medium'), finding('Low')], DEFAULT);
    expect(decision.blocking).toEqual([]);
    expect(decision.warned).toEqual([]);
  });

  it('treats the thresholds as inclusive on both sides', () => {
    const atBlock = evaluateThreshold([finding('High')], { blockOn: 'High', warnOn: 'High' });
    expect(atBlock.blocking).toHaveLength(1);

    const atWarn = evaluateThreshold([finding('Medium')], { blockOn: 'Critical', warnOn: 'Medium' });
    expect(atWarn.warned).toHaveLength(1);
  });

  it('never puts a finding in both lists', () => {
    const findings: LocalFinding[] = ['Critical', 'High', 'Medium', 'Low'].map((severity) =>
      finding(severity as Severity),
    );

    for (const threshold of [
      { blockOn: 'Critical', warnOn: 'High' },
      { blockOn: 'Medium', warnOn: 'Medium' },
      { blockOn: 'Low', warnOn: 'Low' },
      // Deliberately inverted: warnOn is stricter than blockOn.
      { blockOn: 'High', warnOn: 'Critical' },
    ] satisfies ThresholdConfig[]) {
      const decision = evaluateThreshold(findings, threshold);
      const inBoth = decision.blocking.filter((entry) => decision.warned.includes(entry));
      expect(inBoth).toEqual([]);
    }
  });

  it('yields no warnings when warnOn is stricter than blockOn, because blocking wins', () => {
    const decision = evaluateThreshold(
      [finding('Critical'), finding('High')],
      { blockOn: 'High', warnOn: 'Critical' },
    );
    expect(decision.blocking).toHaveLength(2);
    expect(decision.warned).toEqual([]);
  });

  it('counts every finding by severity', () => {
    const decision = evaluateThreshold(
      [finding('Critical'), finding('Critical'), finding('Medium')],
      DEFAULT,
    );
    expect(decision.counts).toEqual({ Critical: 2, High: 0, Medium: 1, Low: 0 });
  });

  it('reports the worst severity present regardless of input order', () => {
    expect(evaluateThreshold([finding('Low'), finding('Critical'), finding('High')], DEFAULT).highest).toBe(
      'Critical',
    );
    expect(evaluateThreshold([finding('Low')], DEFAULT).highest).toBe('Low');
  });

  it('preserves input order within each list', () => {
    const first = finding('Critical', { file: 'a.js', line: 1 });
    const second = finding('Critical', { file: 'b.js', line: 2 });
    const decision = evaluateThreshold([first, second], DEFAULT);
    expect(decision.blocking).toEqual([first, second]);
  });
});
