/**
 * The severity floor Remote Mode runs under (FR-5).
 *
 * The first test in this file is the defect that motivated the module, written
 * out as it was reported: the same SQL injection, Critical from the rule engine
 * and High from the model, which meant Local Mode refused the commit and Remote
 * Mode warned and allowed it. Everything after it is a boundary of that rule —
 * what the floor may and may not reach.
 */

import { describe, expect, it } from '@jest/globals';

import type { Category, Severity } from '../../prompts/security-agent-prompts';
import type { Finding } from '../findings';
import { reconcileWithBaseline } from '../reconcile';

function finding(
  file: string,
  line: number,
  category: Category,
  severity: Severity,
  over: Partial<Finding> = {},
): Finding {
  return {
    file,
    line,
    category,
    ruleId: `rule-for-${category}`,
    severity,
    message: `${severity} ${category}`,
    ...over,
  };
}

describe('reconcileWithBaseline — the severity floor', () => {
  it('raises a remote finding to the rule engine severity for the same class', () => {
    // The reported defect. Same file, same line, same vulnerability — and the
    // two engines disagreed by one tier, which is the difference between a
    // warning and a blocked commit. The rule engine wins, because a regex match
    // is a fact and a model's severity is a judgement.
    const result = reconcileWithBaseline({
      counted: [finding('src/db.js', 12, 'sql_injection', 'High')],
      dismissed: [],
      baseline: [
        finding('src/db.js', 12, 'sql_injection', 'Critical', {
          ruleId: 'sql-string-concatenation',
        }),
      ],
    });

    expect(result.counted).toHaveLength(1);
    expect(result.counted[0]?.severity).toBe('Critical');
    expect(result.reinstated).toEqual([]);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]).toContain('src/db.js');
    expect(result.notes[0]).toContain('sql_injection');
    expect(result.notes[0]).toContain('raised to Critical');
  });

  it('never lowers a severity the AI engine got right, or got dramatic about', () => {
    const result = reconcileWithBaseline({
      counted: [finding('src/db.js', 12, 'sql_injection', 'Critical')],
      dismissed: [],
      baseline: [finding('src/db.js', 12, 'sql_injection', 'High')],
    });

    expect(result.counted[0]?.severity).toBe('Critical');
    expect(result.notes).toEqual([]);
  });

  it('takes the worst the rules found in the group, not the first', () => {
    // A group can hold several rule matches — MD5 and ECB are both
    // `insecure_crypto` and can appear in one file. The floor is the highest of
    // them, which is the one the threshold would have applied in Local Mode.
    const result = reconcileWithBaseline({
      counted: [finding('src/crypto.js', 4, 'insecure_crypto', 'Low')],
      dismissed: [],
      baseline: [
        finding('src/crypto.js', 4, 'insecure_crypto', 'Medium'),
        finding('src/crypto.js', 9, 'insecure_crypto', 'High'),
      ],
    });

    expect(result.counted[0]?.severity).toBe('High');
  });

  it('does not floor a finding in a different file', () => {
    // The match is per file. A Critical query in db.js says nothing about the
    // severity of an unrelated finding in mailer.js, and treating it as though
    // it did would make every file with one injection pattern block everything.
    const result = reconcileWithBaseline({
      counted: [finding('src/mailer.js', 3, 'sql_injection', 'Low')],
      dismissed: [],
      baseline: [finding('src/db.js', 3, 'sql_injection', 'Critical')],
    });

    expect(result.counted[0]?.severity).toBe('Low');
  });

  it('leaves a category the rules cannot produce entirely alone', () => {
    // The categories only Remote Mode can find are the reason for paying for it.
    // No built-in rule emits `logic_bug`, so a rule match in the same file must
    // not drag a logic-bug finding up to its severity.
    const result = reconcileWithBaseline({
      counted: [finding('src/run.js', 40, 'logic_bug', 'Medium')],
      dismissed: [],
      baseline: [finding('src/run.js', 2, 'command_injection', 'Critical')],
    });

    expect(result.counted.map((entry) => entry.severity)).toEqual(['Critical', 'Medium']);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]).toContain('reported no command_injection');
  });

  it('adds a rule-engine finding the AI scan never reported', () => {
    // The same weakness from the other direction. Triage missing a hardcoded key
    // entirely did not merely under-rate it — in Remote Mode the finding did not
    // exist, so a commit Local Mode blocks could sail through a "clean" AI scan.
    const secret = finding('src/config.js', 1, 'hardcoded_secret', 'Critical', {
      ruleId: 'hardcoded-secret-aws-key',
      message: 'Hardcoded AWS access key ID.',
    });

    const result = reconcileWithBaseline({ counted: [], dismissed: [], baseline: [secret] });

    expect(result.counted).toEqual([secret]);
    expect(result.reinstated).toEqual([secret]);
    expect(result.notes[0]).toContain('reported no hardcoded_secret');
    expect(result.notes[0]).toContain('src/config.js');
  });

  it('does not add a rule finding for a group the AI already reported', () => {
    // Deliberate, and the one place this trades completeness for quiet. Both
    // engines pointing at one issue would render as two rows for the same line,
    // and duplicate rows are what gets a pre-commit gate switched off. The commit
    // outcome is unaffected: the group is floored either way.
    const result = reconcileWithBaseline({
      counted: [finding('src/db.js', 12, 'sql_injection', 'High')],
      dismissed: [],
      baseline: [
        finding('src/db.js', 5, 'sql_injection', 'Critical'),
        finding('src/db.js', 12, 'sql_injection', 'Critical'),
        finding('src/db.js', 30, 'sql_injection', 'Critical'),
      ],
    });

    expect(result.counted).toHaveLength(1);
    expect(result.counted[0]?.line).toBe(12);
    expect(result.counted[0]?.severity).toBe('Critical');
    expect(result.reinstated).toEqual([]);
  });

  it('overrules a deep-analysis dismissal of a class the rules report', () => {
    // A dismissal is a downgrade to nothing, so it is the extreme case of the
    // same problem — and the one place a second opinion could silently remove
    // the only protection a deterministic match provided.
    const result = reconcileWithBaseline({
      counted: [],
      dismissed: [
        finding('src/db.js', 12, 'sql_injection', 'Low', {
          message: 'This query is parameterised and cannot be injected.',
        }),
      ],
      baseline: [
        finding('src/db.js', 12, 'sql_injection', 'Critical', {
          ruleId: 'sql-string-concatenation',
        }),
      ],
    });

    expect(result.dismissed).toEqual([]);
    expect(result.counted).toHaveLength(1);
    expect(result.counted[0]?.severity).toBe('Critical');
    expect(result.notes).toContainEqual(expect.stringContaining('as a false positive'));
    // The model's reasoning is kept in the note rather than discarded. It is the
    // only signal that this rule match might be the false positive — a
    // parameterised query the pattern was too blunt to recognise — and a
    // developer overruled without that sentence has nowhere to look.
    expect(result.notes).toContainEqual(expect.stringContaining('parameterised'));
  });

  it('keeps a dismissal the rules say nothing about', () => {
    // Stage 2 dropping triage noise is the whole reason it is paid for, and
    // nothing in the rule set speaks to an unhandled exception.
    const dismissal = finding('src/io.js', 7, 'unhandled_exception', 'Medium');

    const result = reconcileWithBaseline({
      counted: [],
      dismissed: [dismissal],
      baseline: [finding('src/io.js', 90, 'hardcoded_secret', 'High')],
    });

    expect(result.dismissed).toEqual([dismissal]);
  });

  it('changes nothing at all when there is no baseline', () => {
    // The no-baseline path is what every existing remote scan takes, and what a
    // Local Mode scan would take. It has to be an exact pass-through, or this
    // module would be quietly editing results it was never asked about.
    const counted = [finding('src/db.js', 12, 'sql_injection', 'High')];
    const dismissed = [finding('src/io.js', 7, 'unhandled_exception', 'Medium')];

    const result = reconcileWithBaseline({ counted, dismissed, baseline: [] });

    expect(result.counted).toEqual(counted);
    expect(result.dismissed).toEqual(dismissed);
    expect(result.reinstated).toEqual([]);
    expect(result.notes).toEqual([]);
  });

  it('restores line order within a file without reordering the files', () => {
    // `counted` arrives in pipeline order, which puts findings that matched no
    // hunk ahead of the analysed ones. A file could therefore be listed at line
    // 900 and then line 2.
    const result = reconcileWithBaseline({
      counted: [
        finding('src/a.js', 900, 'logic_bug', 'Low'),
        finding('src/b.js', 1, 'logic_bug', 'Low'),
        finding('src/a.js', 2, 'logic_bug', 'Low'),
      ],
      dismissed: [],
      baseline: [],
    });

    expect(result.counted.map((entry) => `${entry.file}:${entry.line}`)).toEqual([
      'src/a.js:2',
      'src/a.js:900',
      'src/b.js:1',
    ]);
  });

  it('summarises a group in one note rather than one per finding', () => {
    const result = reconcileWithBaseline({
      counted: [
        finding('src/db.js', 12, 'sql_injection', 'High'),
        finding('src/db.js', 30, 'sql_injection', 'Medium'),
      ],
      dismissed: [],
      baseline: [
        finding('src/db.js', 12, 'sql_injection', 'Critical'),
        finding('src/db.js', 30, 'sql_injection', 'Critical'),
      ],
    });

    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]).toContain('2 findings');
  });
});
