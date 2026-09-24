/**
 * Validating model output.
 *
 * The tests here are mostly about what is REFUSED, because that is the part
 * nobody notices is missing. A validator that accepts everything passes every
 * happy-path test ever written and still lets an invented severity reach a
 * threshold comparison that then quietly never fires.
 *
 * The one asymmetry worth stating plainly, because it looks like an
 * inconsistency until you see why: an unknown `category` is coerced, an unknown
 * `severity` rejects the whole finding. Category is a label; severity is the
 * threshold's only input.
 */

import { describe, expect, it } from '@jest/globals';

import { parsePatchResponse, parseTriageResponse } from '../parse';

const FILES = new Set(['src/db.js', 'src/run.js']);

const GOOD_FINDING = {
  file: 'src/db.js',
  line_range: [2, 2],
  severity: 'Critical',
  category: 'sql_injection',
  summary: 'Request data reaches the query.',
};

const GOOD_PATCH = {
  file: 'src/db.js',
  line_range: [2, 2],
  severity: 'Critical',
  category: 'sql_injection',
  explanation: 'Concatenation lets the caller rewrite the query.',
  // No trailing newline: the parser trims the patch, because stray whitespace
  // at either edge is exactly what stops a diff applying cleanly in Phase 5.
  suggested_patch: '--- a/src/db.js\n+++ b/src/db.js\n@@ -2 +2 @@\n-  db.query(sql + name)\n+  db.query(sql, [name])',
  confidence: 'high',
};

const triage = (entry: unknown): ReturnType<typeof parseTriageResponse> =>
  parseTriageResponse(JSON.stringify({ findings: entry === undefined ? [] : [entry] }), {
    knownFiles: FILES,
  });

describe('parseTriageResponse — accepted input', () => {
  it('parses a well-formed finding', () => {
    const result = triage(GOOD_FINDING);

    expect(result.value).toHaveLength(1);
    expect(result.value[0]).toEqual(GOOD_FINDING);
    expect(result.rejected).toEqual([]);
  });

  it('accepts an empty findings array as "nothing found"', () => {
    expect(parseTriageResponse('{"findings":[]}', { knownFiles: FILES }).value).toEqual([]);
  });

  it('treats a missing findings field as nothing found', () => {
    expect(parseTriageResponse('{}', { knownFiles: FILES }).value).toEqual([]);
  });

  it('strips a markdown fence rather than failing the scan over formatting', () => {
    const fenced = '```json\n{"findings":[]}\n```';

    expect(parseTriageResponse(fenced, { knownFiles: FILES }).value).toEqual([]);
  });

  it('accepts a bare fence with no language tag', () => {
    expect(parseTriageResponse('```\n{"findings":[]}\n```', { knownFiles: FILES }).value).toEqual([]);
  });

  it('normalises an echoed diff path', () => {
    // The model is shown `b/src/db.js` in the +++ line, so quoting it back
    // verbatim is expected rather than wrong.
    const result = parseTriageResponse(
      JSON.stringify({ findings: [{ ...GOOD_FINDING, file: 'b/src/db.js' }] }),
      { knownFiles: FILES },
    );

    expect(result.value[0]?.file).toBe('src/db.js');
  });
});

describe('parseTriageResponse — refused input', () => {
  it('rejects a finding for a file that was not in the diff', () => {
    const result = triage({ ...GOOD_FINDING, file: 'src/invented.js' });

    expect(result.value).toHaveLength(0);
    expect(result.rejected[0]).toContain('not in the diff');
  });

  it('rejects a finding with no file path', () => {
    const result = triage({ ...GOOD_FINDING, file: '   ' });

    expect(result.value).toHaveLength(0);
    expect(result.rejected[0]).toContain('no file path');
  });

  it('rejects an unusable severity instead of guessing one', () => {
    // The important one. Severity is what `evaluateThreshold` compares against,
    // so a guessed default either blocks a commit that should have passed or
    // waves through one that should not. Admitting the entry is unusable is the
    // only outcome that cannot silently mis-gate.
    for (const severity of ['Very Bad', 'critical', '', 3, null, undefined]) {
      const result = triage({ ...GOOD_FINDING, severity });

      expect(result.value).toHaveLength(0);
      expect(result.rejected[0]).toContain('unusable severity');
    }
  });

  it('coerces an unknown category rather than discarding a real vulnerability', () => {
    // The other half of the asymmetry: a taxonomy typo should cost a group
    // heading, not a finding.
    const result = triage({ ...GOOD_FINDING, category: 'quantum_flux' });

    expect(result.value).toHaveLength(1);
    expect(result.value[0]?.category).toBe('other');
  });

  it('rejects a missing category by coercing, not by refusing', () => {
    const result = triage({ ...GOOD_FINDING, category: undefined });

    expect(result.value[0]?.category).toBe('other');
  });

  it('rejects a malformed line_range', () => {
    for (const line_range of [
      [0, 0],
      [5, 2],
      [2],
      [2, 2, 2],
      ['2', '2'],
      'line 2',
      null,
      undefined,
      [1.5, 2],
    ]) {
      const result = triage({ ...GOOD_FINDING, line_range });

      expect(result.value).toHaveLength(0);
      expect(result.rejected[0]).toContain('no usable line_range');
    }
  });

  it('rejects a missing or empty summary', () => {
    for (const summary of [undefined, '', '   ', 42, { text: 'hi' }]) {
      const result = triage({ ...GOOD_FINDING, summary });

      expect(result.value).toHaveLength(0);
      expect(result.rejected[0]).toContain('no summary');
    }
  });

  it('rejects an entry that is not an object', () => {
    for (const entry of ['a string', 42, null, [], true]) {
      const result = triage(entry);

      expect(result.value).toHaveLength(0);
      expect(result.rejected).toHaveLength(1);
    }
  });

  it('keeps the good entries and reports only the bad ones', () => {
    const result = parseTriageResponse(
      JSON.stringify({ findings: [GOOD_FINDING, { ...GOOD_FINDING, severity: 'Nope' }] }),
      { knownFiles: FILES },
    );

    expect(result.value).toHaveLength(1);
    expect(result.rejected).toHaveLength(1);
  });

  it('caps a runaway response rather than turning it into thousands of calls', () => {
    // Stage 2 makes one request per finding. An unguarded loop would spend the
    // whole cap on a single malformed answer.
    const many = Array.from({ length: 250 }, () => GOOD_FINDING);
    const result = parseTriageResponse(JSON.stringify({ findings: many }), { knownFiles: FILES });

    expect(result.value).toHaveLength(200);
    expect(result.rejected.join(' ')).toContain('250 findings');
  });

  it('truncates an essay of a summary', () => {
    const result = triage({ ...GOOD_FINDING, summary: 'x'.repeat(5_000) });

    expect(result.value[0]?.summary.length).toBeLessThan(2_100);
    expect(result.value[0]?.summary.endsWith('…')).toBe(true);
  });
});

describe('parseTriageResponse — input that is not JSON', () => {
  it('throws so the caller can treat it as a provider failure', () => {
    expect(() => parseTriageResponse('Here are the issues I found:', { knownFiles: FILES })).toThrow(
      /not valid JSON/,
    );
  });

  it('throws when the JSON is not an object', () => {
    expect(() => parseTriageResponse('"a string"', { knownFiles: FILES })).toThrow(/not a JSON object/);
  });

  it('throws when findings is not an array', () => {
    expect(() => parseTriageResponse('{"findings":"none"}', { knownFiles: FILES })).toThrow(
      /was not an array/,
    );
  });
});

describe('parsePatchResponse', () => {
  const parse = (body: unknown): ReturnType<typeof parsePatchResponse> =>
    parsePatchResponse(typeof body === 'string' ? body : JSON.stringify(body), FILES);

  it('parses a well-formed patch suggestion', () => {
    const result = parse(GOOD_PATCH);

    expect(result.value).toEqual(GOOD_PATCH);
    expect(result.rejected).toEqual([]);
  });

  it('treats an empty suggested_patch as a valid false-positive signal', () => {
    // Not a parse failure: PATCH_SYSTEM_PROMPT documents an empty patch as the
    // way to say "this was not a real problem", and the pipeline relies on it to
    // drop over-reported findings.
    for (const suggested_patch of ['', '   ', undefined, null]) {
      const result = parse({ ...GOOD_PATCH, suggested_patch });

      expect(result.value).not.toBeNull();
      expect(result.value?.suggested_patch).toBe('');
      expect(result.rejected).toEqual([]);
    }
  });

  it('refuses a non-string patch rather than reading it as "not a problem"', () => {
    // Coercing this to '' would turn a malformed answer into a confident
    // all-clear — the one direction of error that must never be silent.
    const result = parse({ ...GOOD_PATCH, suggested_patch: 42 });

    expect(result.value).toBeNull();
    expect(result.rejected[0]).toContain('non-string suggested_patch');
  });

  it('refuses a result for a file that was not in the diff', () => {
    const result = parse({ ...GOOD_PATCH, file: 'src/invented.js' });

    expect(result.value).toBeNull();
    expect(result.rejected[0]).toContain('not in the diff');
  });

  it('refuses an unusable severity', () => {
    const result = parse({ ...GOOD_PATCH, severity: 'Catastrophic' });

    expect(result.value).toBeNull();
    expect(result.rejected[0]).toContain('unusable severity');
  });

  it('refuses a result with no explanation', () => {
    const result = parse({ ...GOOD_PATCH, explanation: '  ' });

    expect(result.value).toBeNull();
    expect(result.rejected[0]).toContain('no explanation');
  });

  it('falls back to low confidence, the direction that makes a human look harder', () => {
    const result = parse({ ...GOOD_PATCH, confidence: 'certain' });

    expect(result.value?.confidence).toBe('low');
    expect(result.rejected).toEqual([]);
  });

  it('falls back to a single-line range and an "other" category', () => {
    const result = parse({ ...GOOD_PATCH, line_range: 'line 2', category: 'nonsense' });

    expect(result.value?.line_range).toEqual([1, 1]);
    expect(result.value?.category).toBe('other');
  });

  it('throws when the response is not JSON', () => {
    expect(() => parsePatchResponse('I cannot help with that.', FILES)).toThrow(/not valid JSON/);
  });

  it('throws when the JSON is an array', () => {
    expect(() => parsePatchResponse('[]', FILES)).toThrow(/not a JSON object/);
  });
});
