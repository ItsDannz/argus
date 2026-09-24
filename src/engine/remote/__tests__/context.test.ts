/**
 * Mapping Stage-1 findings back onto hunks.
 *
 * This is where the cost of a remote scan is decided — one Stage-2 call per
 * hunk chosen here — so the tests are about which hunks get chosen and, just as
 * importantly, which findings are handed back rather than dropped.
 */

import { describe, expect, it } from '@jest/globals';

import type { ScanFinding } from '../../../prompts/security-agent-prompts';
import { selectFlaggedHunks } from '../context';

const DIFF = [
  'diff --git a/src/db.js b/src/db.js',
  'index 1111111..2222222 100644',
  '--- a/src/db.js',
  '+++ b/src/db.js',
  '@@ -10,3 +10,4 @@ function findUser(db, name) {',
  '   const q = "SELECT * FROM users";',
  '+  return db.query(q + name);',
  ' }',
  '   // trailing',
  '@@ -50,3 +51,3 @@ function other(db) {',
  '   const x = 1;',
  '-  const y = 2;',
  '+  const y = eval(input);',
  '   return y;',
  'diff --git a/src/run.js b/src/run.js',
  'index 3333333..4444444 100644',
  '--- a/src/run.js',
  '+++ b/src/run.js',
  '@@ -1,2 +1,3 @@',
  ' const fs = require("fs");',
  '+execSync("rm -rf " + dir);',
  '',
].join('\n');

function finding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    file: 'src/db.js',
    line_range: [12, 12],
    severity: 'High',
    category: 'sql_injection',
    summary: 'Concatenated query.',
    ...overrides,
  };
}

describe('selectFlaggedHunks', () => {
  it('attaches a finding to the hunk containing its line', () => {
    const result = selectFlaggedHunks(DIFF, [finding()], 5);

    expect(result.selected).toHaveLength(1);
    expect(result.selected[0]?.file).toBe('src/db.js');
    expect(result.selected[0]?.lineMatched).toBe(true);
    // The hunk text is the code the model will reason about, so it has to be
    // the added line plus its context, with the diff markers intact.
    expect(result.selected[0]?.text).toContain('+  return db.query(q + name);');
    expect(result.selected[0]?.text).toContain('SELECT * FROM users');
    // ...and nothing from the other hunk in the same file.
    expect(result.selected[0]?.text).not.toContain('eval(input)');
  });

  it('picks the second hunk for a line inside it', () => {
    const result = selectFlaggedHunks(DIFF, [finding({ line_range: [52, 52] })], 5);

    expect(result.selected[0]?.text).toContain('+  const y = eval(input);');
    expect(result.selected[0]?.text).not.toContain('db.query');
  });

  it('makes one call per hunk, not one per finding', () => {
    // Two findings on the same code are the same question. Charging twice would
    // make the cap lie about how much of the diff was actually covered.
    const result = selectFlaggedHunks(
      DIFF,
      [
        finding({ category: 'sql_injection', severity: 'High' }),
        finding({ category: 'logic_bug', severity: 'Medium' }),
      ],
      5,
    );

    expect(result.selected).toHaveLength(1);
    expect(result.selected[0]?.findings).toHaveLength(2);
    // The hunk takes its worst finding's severity — the cap sorts on this.
    expect(result.selected[0]?.severity).toBe('High');
  });

  it('sorts worst first, so the cap cuts the least bad', () => {
    const result = selectFlaggedHunks(
      DIFF,
      [
        finding({ line_range: [52, 52], severity: 'Low', category: 'code_execution' }),
        finding({ line_range: [12, 12], severity: 'Critical', category: 'sql_injection' }),
        finding({ file: 'src/run.js', line_range: [2, 2], severity: 'High', category: 'command_injection' }),
      ],
      5,
    );

    expect(result.selected.map((hunk) => hunk.severity)).toEqual(['Critical', 'High', 'Low']);
  });

  it('splits at the cap, keeping the worst hunks', () => {
    const result = selectFlaggedHunks(
      DIFF,
      [
        finding({ line_range: [52, 52], severity: 'Low', category: 'code_execution' }),
        finding({ line_range: [12, 12], severity: 'Critical', category: 'sql_injection' }),
        finding({ file: 'src/run.js', line_range: [2, 2], severity: 'High', category: 'command_injection' }),
      ],
      2,
    );

    expect(result.selected.map((hunk) => hunk.file)).toEqual(['src/db.js', 'src/run.js']);
    // Returned in full, not counted: the report has to name what was skipped.
    expect(result.beyondCap).toHaveLength(1);
    expect(result.beyondCap[0]?.severity).toBe('Low');
    expect(result.beyondCap[0]?.file).toBe('src/db.js');
  });

  it('selects nothing when the cap is zero, without losing the findings', () => {
    const result = selectFlaggedHunks(DIFF, [finding()], 0);

    expect(result.selected).toHaveLength(0);
    expect(result.beyondCap).toHaveLength(1);
  });

  it('falls back to the nearest hunk when the line is outside every one', () => {
    // The model's line numbers can disagree with ours. Reasoning about the
    // nearest hunk beats dropping the finding — but the disagreement is carried
    // forward, because it makes any resulting patch less trustworthy.
    const result = selectFlaggedHunks(DIFF, [finding({ line_range: [900, 900] })], 5);

    expect(result.selected).toHaveLength(1);
    expect(result.selected[0]?.lineMatched).toBe(false);
    // The second hunk (51–53) is nearer to 900 than the first (10–13).
    expect(result.selected[0]?.text).toContain('eval(input)');
  });

  it('hands back a finding whose file is absent from the diff', () => {
    const result = selectFlaggedHunks(DIFF, [finding({ file: 'src/ghost.js' })], 5);

    expect(result.selected).toHaveLength(0);
    expect(result.unmatched).toHaveLength(1);
    expect(result.unmatched[0]?.file).toBe('src/ghost.js');
  });

  it('hands back a finding for a file that has no hunks', () => {
    // A binary file parses as a real file with zero hunks, so this is a
    // different path from a missing file and needs its own guard.
    const binary = [
      'diff --git a/assets/logo.png b/assets/logo.png',
      'index 5555555..6666666 100644',
      'Binary files a/assets/logo.png and b/assets/logo.png differ',
    ].join('\n');

    const result = selectFlaggedHunks(binary, [finding({ file: 'assets/logo.png' })], 5);

    expect(result.selected).toHaveLength(0);
    expect(result.unmatched).toHaveLength(1);
  });

  it('marks a hunk whose text carries a redaction placeholder', () => {
    // The flag is what lets the pipeline refuse to hand back a patch quoting a
    // line it never actually sent.
    const redacted = DIFF.replace(
      '+  return db.query(q + name);',
      '+  return db.query(q + "«REDACTED:assigned-secret»");',
    );

    const result = selectFlaggedHunks(redacted, [finding()], 5);

    expect(result.selected[0]?.redacted).toBe(true);
  });

  it('leaves the flag false when there is nothing redacted', () => {
    const result = selectFlaggedHunks(DIFF, [finding()], 5);

    expect(result.selected[0]?.redacted).toBe(false);
  });

  it('reports every finding across the selected hunks, for the caller to count', () => {
    const findings = [
      finding({ line_range: [12, 12], severity: 'Critical' }),
      finding({ line_range: [12, 12], severity: 'Medium', category: 'logic_bug' }),
      finding({ file: 'src/run.js', line_range: [2, 2], severity: 'High', category: 'command_injection' }),
    ];

    const result = selectFlaggedHunks(DIFF, findings, 5);

    const gathered = result.selected.flatMap((hunk) => hunk.findings);
    expect(gathered).toHaveLength(3);
    expect(result.unmatched).toHaveLength(0);
    expect(result.beyondCap).toHaveLength(0);
  });

  it('handles findings in an order that does not match the diff', () => {
    // Nothing guarantees the model answers in diff order, and the stable-sort
    // tiebreak is what keeps the selection reproducible when severities match.
    const result = selectFlaggedHunks(
      DIFF,
      [
        finding({ file: 'src/run.js', line_range: [2, 2], severity: 'Critical', category: 'command_injection' }),
        finding({ line_range: [12, 12], severity: 'Critical', category: 'sql_injection' }),
      ],
      5,
    );

    expect(result.selected.map((hunk) => hunk.file)).toEqual(['src/run.js', 'src/db.js']);
  });

  it('returns nothing for an empty set of findings', () => {
    const result = selectFlaggedHunks(DIFF, [], 5);

    expect(result.selected).toEqual([]);
    expect(result.beyondCap).toEqual([]);
    expect(result.unmatched).toEqual([]);
  });
});
