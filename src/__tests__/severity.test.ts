import { describe, expect, it } from '@jest/globals';

import { SEVERITIES, SEVERITY_RANK, isSeverity, severityAtLeast } from '../severity';

describe('severity ordering', () => {
  it('lists severities worst first', () => {
    expect(SEVERITIES).toEqual(['Critical', 'High', 'Medium', 'Low']);
  });

  it('ranks them in descending order', () => {
    expect(SEVERITY_RANK.Critical).toBeGreaterThan(SEVERITY_RANK.High);
    expect(SEVERITY_RANK.High).toBeGreaterThan(SEVERITY_RANK.Medium);
    expect(SEVERITY_RANK.Medium).toBeGreaterThan(SEVERITY_RANK.Low);
  });

  it('keeps SEVERITIES and SEVERITY_RANK in the same order', () => {
    // If these two ever disagree, a summary can describe a finding as
    // "the worst" while the threshold logic classifies it differently.
    const ranks = SEVERITIES.map((severity) => SEVERITY_RANK[severity]);
    expect(ranks).toEqual([...ranks].sort((a, b) => b - a));
  });
});

describe('severityAtLeast', () => {
  it('is inclusive at the threshold', () => {
    expect(severityAtLeast('Critical', 'Critical')).toBe(true);
    expect(severityAtLeast('High', 'High')).toBe(true);
  });

  it('is true above the threshold', () => {
    expect(severityAtLeast('Critical', 'High')).toBe(true);
    expect(severityAtLeast('Medium', 'Low')).toBe(true);
  });

  it('is false below the threshold', () => {
    expect(severityAtLeast('High', 'Critical')).toBe(false);
    expect(severityAtLeast('Low', 'Medium')).toBe(false);
  });
});

describe('isSeverity', () => {
  it('accepts exactly the four names', () => {
    for (const severity of SEVERITIES) expect(isSeverity(severity)).toBe(true);
  });

  it('rejects case variants, which are the likely typo in a hand-edited config', () => {
    expect(isSeverity('critical')).toBe(false);
    expect(isSeverity('CRITICAL')).toBe(false);
    expect(isSeverity('High ')).toBe(false);
  });

  it('rejects invented names', () => {
    expect(isSeverity('Severe')).toBe(false);
    expect(isSeverity('')).toBe(false);
  });

  it('rejects Object.prototype members that a naive `in` check would accept', () => {
    // `'constructor' in SEVERITY_RANK` is true, because it is inherited. A
    // config saying { "blockOn": "constructor" } would then be "valid" and
    // SEVERITY_RANK[value] would be a function, producing a NaN comparison —
    // so every finding would silently compare false and nothing would ever
    // block again.
    expect(isSeverity('constructor')).toBe(false);
    expect(isSeverity('toString')).toBe(false);
    expect(isSeverity('hasOwnProperty')).toBe(false);
    expect(isSeverity('__proto__')).toBe(false);
  });

  it('rejects non-strings', () => {
    expect(isSeverity(null)).toBe(false);
    expect(isSeverity(undefined)).toBe(false);
    expect(isSeverity(4)).toBe(false);
    expect(isSeverity({})).toBe(false);
    expect(isSeverity(['Critical'])).toBe(false);
  });
});
