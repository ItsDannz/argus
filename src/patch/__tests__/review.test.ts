/**
 * The review loop (FR-7), driven through its injected seams.
 *
 * `review.ts` is where the decisions live — whether a failure ends a finding,
 * whether an edit is trusted, what happens to a patch that cannot be parsed —
 * and every one of those is a behaviour a developer will meet at the worst
 * possible moment. So the loop is tested here with a scripted answerer, a fake
 * editor and a fake applier: no TTY, no editor process, no filesystem, no model.
 *
 * The two properties most worth protecting, both of which have a test below:
 * nothing is written without an explicit [a]pply, and a failure returns to the
 * prompt rather than dropping the finding or discarding the edit.
 */

import { describe, expect, it } from '@jest/globals';

import type { ApplyRequest, ApplyResult } from '../apply';
import type { EditOutcome } from '../editor';
import { reviewPatches, type PatchCandidate, type ReviewChoice, type ReviewQuestion } from '../review';

/** Well-formed as the model should have written it: header, correct counts. */
const GOOD_PATCH = [
  '--- a/src/math.js',
  '+++ b/src/math.js',
  '@@ -1,3 +1,3 @@',
  ' const add = (a, b) => a + b;',
  '-const sub = (a, b) => a - b;',
  '+const sub = (a, b) => a + b;',
  ' const mul = (a, b) => a * b;',
].join('\n');

/**
 * The shape the live provider actually returns: no file header, and a hunk
 * header counting two removals and two additions over a body with two removals
 * and one addition. See normalise.ts — this is the defect Phase 5 exists partly
 * to handle, so the loop is exercised with the real shape rather than with a
 * tidy patch the model has never once produced.
 */
const DEFECTIVE_PATCH = [
  '@@ -11,2 +11,2 @@',
  '-  const sql = "SELECT id FROM users WHERE id = " + userId;',
  '-  db.query(sql);',
  '+  db.query("SELECT id FROM users WHERE id = ?", [userId]);',
].join('\n');

const EDITED_PATCH = [
  '--- a/src/math.js',
  '+++ b/src/math.js',
  '@@ -1,3 +1,3 @@',
  ' const add = (a, b) => a + b;',
  '-const sub = (a, b) => a - b;',
  '+const sub = (a, b) => a + b; // reviewer note',
  ' const mul = (a, b) => a * b;',
].join('\n');

function candidate(over: Partial<PatchCandidate> = {}): PatchCandidate {
  return {
    file: 'src/math.js',
    line: 2,
    severity: 'Critical',
    category: 'logic_bug',
    explanation: 'The subtraction looks like it should be addition.',
    patch: GOOD_PATCH,
    ...over,
  };
}

/**
 * Runs the loop with scripted answers.
 *
 * The answerer also records the questions it was asked, so an assertion can be
 * about what the developer was SHOWN, not only about what happened — a prompt
 * that offered [a]pply for a patch that cannot be applied would be a bug the
 * outcome alone would not reveal.
 */
async function run(options: {
  candidates?: PatchCandidate[];
  answers: ReviewChoice[];
  edit?: (patch: string) => EditOutcome;
  apply?: (request: ApplyRequest) => ApplyResult;
}) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const asked: ReviewQuestion[] = [];
  const edited: string[] = [];
  const applied: ApplyRequest[] = [];
  const onApplied: string[] = [];
  const queue = [...options.answers];

  const summary = await reviewPatches({
    candidates: options.candidates ?? [candidate()],
    repoRoot: '/scratch',
    write: (text) => void stdout.push(text),
    writeError: (text) => void stderr.push(text),
    ask: async (question) => {
      asked.push(question);
      const next = queue.shift();
      if (next === undefined) throw new Error(`the loop asked a ${asked.length}th question with no answer scripted`);
      return next;
    },
    edit: async (patch) => {
      edited.push(patch);
      return options.edit === undefined
        ? { ok: false, reason: 'no editor scripted' }
        : options.edit(patch);
    },
    apply: async (request) => {
      applied.push(request);
      return options.apply === undefined
        ? { ok: true, content: 'stub', changedLines: [2] }
        : options.apply(request);
    },
    onApplied: (file) => onApplied.push(file),
  });

  return {
    summary,
    asked,
    edited,
    applied,
    onApplied,
    out: stdout.join(''),
    err: stderr.join(''),
  };
}

describe('reviewPatches — the happy paths', () => {
  it('applies an accepted patch and records the file', async () => {
    const result = await run({ answers: ['apply'] });

    expect(result.applied).toHaveLength(1);
    expect(result.applied[0]?.file).toBe('src/math.js');
    expect(result.summary.appliedFiles).toEqual(['src/math.js']);
    expect(result.summary.reviewed).toEqual([
      { file: 'src/math.js', line: 2, outcome: 'applied' },
    ]);
    expect(result.out).toContain('applied the patch to src/math.js');
    expect(result.out).toContain('1 line changed');
  });

  it('shows the patch for [v]iew without writing anything', async () => {
    const result = await run({ answers: ['view', 'apply'] });

    expect(result.applied).toHaveLength(1);
    expect(result.out).toContain('const sub = (a, b) => a + b;');
    // The applied request is what matters: viewing must not reach the applier.
    expect(result.asked).toHaveLength(2);
    expect(result.asked[0]?.canApply).toBe(true);
  });

  it('applies the developer`s edited patch, not the model`s', async () => {
    const result = await run({
      answers: ['edit', 'apply'],
      edit: () => ({ ok: true, text: EDITED_PATCH }),
    });

    expect(result.edited).toHaveLength(1);
    expect(result.applied).toHaveLength(1);
    expect(result.applied[0]?.patch.text).toBe(EDITED_PATCH);
    expect(result.applied[0]?.patch.repairs).toEqual([]);
    // The question that follows an edit says so — the developer is looking at
    // their own text, and a prompt still calling it "the model's patch" would be
    // describing something they are no longer reviewing.
    expect(result.asked[1]?.edited).toBe(true);
  });

  it('skips a finding the developer does not want, and says so', async () => {
    const result = await run({ answers: ['skip'] });

    expect(result.applied).toHaveLength(0);
    expect(result.summary.appliedFiles).toEqual([]);
    expect(result.summary.reviewed).toEqual([{ file: 'src/math.js', line: 2, outcome: 'skipped' }]);
    expect(result.onApplied).toEqual([]);
  });

  it('announces a repair before the developer is asked to trust the patch', async () => {
    const result = await run({
      candidates: [candidate({ file: 'server/routes/users.js', patch: DEFECTIVE_PATCH })],
      answers: ['skip'],
    });

    expect(result.err).toContain('repaired the patch for server/routes/users.js:2');
    expect(result.err).toContain('added the missing file header');
    // The repair is a property of the question too, so the prompt can carry it.
    expect(result.asked[0]?.repairs.length).toBeGreaterThan(0);
  });

  it('says nothing about repairs when the model wrote a well-formed patch', async () => {
    const result = await run({ answers: ['skip'] });

    expect(result.err).not.toContain('repaired the patch');
    expect(result.asked[0]?.repairs).toEqual([]);
  });

  it('reports a file once, however many patches it receives', async () => {
    const result = await run({
      candidates: [candidate(), candidate({ line: 7 })],
      answers: ['apply', 'apply'],
    });

    expect(result.applied).toHaveLength(2);
    expect(result.summary.appliedFiles).toEqual(['src/math.js']);
    // The callback is what survives an interrupt, so it must not fire twice for
    // one file and make the caller report two staged files.
    expect(result.onApplied).toEqual(['src/math.js']);
  });
});

describe('reviewPatches — a failure returns to the prompt', () => {
  it('re-prompts when the edit comes back broken, and keeps the finding', async () => {
    const result = await run({
      answers: ['edit', 'skip'],
      // `...` where code was elided: refused by design, because there is no way
      // to know what it replaces.
      edit: () => ({ ok: true, text: '@@ -1,3 +1,3 @@\n ...\n' }),
    });

    expect(result.asked).toHaveLength(2);
    expect(result.err).toContain('the edited patch is not usable');
    expect(result.applied).toHaveLength(0);
    // Finding kept, and honestly recorded as skipped rather than lost.
    expect(result.summary.reviewed).toEqual([{ file: 'src/math.js', line: 2, outcome: 'skipped' }]);
  });

  it('lets a broken edit be fixed, and applies the fixed version', async () => {
    let attempt = 0;
    const result = await run({
      answers: ['edit', 'edit', 'apply'],
      edit: () => {
        attempt += 1;
        return attempt === 1 ? { ok: true, text: 'not a patch at all' } : { ok: true, text: EDITED_PATCH };
      },
    });

    expect(result.err).toContain('the edited patch is not usable');
    expect(result.applied).toHaveLength(1);
    expect(result.applied[0]?.patch.text).toBe(EDITED_PATCH);
  });

  it('re-prompts when the editor was abandoned, and does not count it as an edit', async () => {
    const result = await run({
      answers: ['edit', 'skip'],
      edit: () => ({ ok: false, reason: 'the patch was left empty, so the edit was abandoned' }),
    });

    expect(result.err).toContain('the patch was left empty');
    expect(result.asked[1]?.edited).toBe(false);
    expect(result.applied).toHaveLength(0);
  });

  it('re-prompts when the applier refuses, rather than dropping the finding', async () => {
    // The applier refuses once — a stale patch, or a file that moved on since
    // the scan — and accepts the second time. What matters is that the refusal
    // is not the end of the finding: the developer gets the reason and the same
    // four options back.
    let attempts = 0;
    const result = await run({
      answers: ['apply', 'apply'],
      apply: () => {
        attempts += 1;
        return attempts === 1
          ? { ok: false, reason: 'the patch does not fit this file' }
          : { ok: true, content: 'stub', changedLines: [2] };
      },
    });

    expect(result.applied).toHaveLength(2);
    expect(result.err).toContain('could not apply the patch — the patch does not fit this file');
    expect(result.asked).toHaveLength(2);
    expect(result.summary.reviewed[0]?.outcome).toBe('applied');
  });

  it('reports a misplaced edit and lets it be skipped instead', async () => {
    const result = await run({
      answers: ['apply', 'skip'],
      apply: () => ({ ok: false, reason: 'the edit would land on line 40, outside every range the patch declares' }),
    });

    expect(result.err).toContain('outside every range');
    expect(result.summary.appliedFiles).toEqual([]);
    expect(result.summary.reviewed[0]?.outcome).toBe('skipped');
  });
});

describe('reviewPatches — a patch that cannot be used at all', () => {
  it('offers no [a]pply and records the finding as unusable', async () => {
    const result = await run({
      candidates: [candidate({ patch: 'I could not produce a patch for this file.' })],
      answers: ['skip'],
    });

    expect(result.asked[0]?.canApply).toBe(false);
    expect(result.summary.appliedFiles).toEqual([]);
    expect(result.summary.reviewed[0]?.outcome).toBe('unusable');
    expect(result.summary.reviewed[0]?.reason).toContain('no hunk header');
  });

  it('shows the reason on [v]iew, so "unusable" is not a dead end', async () => {
    const result = await run({
      candidates: [candidate({ patch: 'I could not produce a patch for this file.' })],
      answers: ['view', 'skip'],
    });

    expect(result.out).toContain('the patch could not be used');
    expect(result.out).toContain('no hunk header');
    // And the model's own words, so the developer can judge the explanation.
    expect(result.out).toContain('I could not produce a patch for this file.');
  });

  /**
   * The finding the pipeline produced no patch for at all.
   *
   * This is not the same situation as a patch the model wrote badly: there is no
   * text to show, and the parser's own complaint about an empty string ("the
   * patch contains no hunk header") describes the symptom while hiding the cause.
   * The pipeline's reason is the one that tells a developer whether their run is
   * broken or the model simply had nothing to offer.
   */
  it('reports the pipeline`s reason for a finding that never had a patch', async () => {
    const result = await run({
      candidates: [
        candidate({
          patch: '',
          reason: 'deep analysis did not produce a patch for this finding — its answer was discarded',
        }),
      ],
      answers: ['skip'],
    });

    expect(result.asked[0]?.canApply).toBe(false);
    expect(result.summary.reviewed[0]?.outcome).toBe('unusable');
    expect(result.summary.reviewed[0]?.reason).toContain('its answer was discarded');
    // Not the parser's account of an empty string, which says nothing useful.
    expect(result.summary.reviewed[0]?.reason).not.toContain('no hunk header');
  });

  it('says no patch was produced when [v]iew has nothing to show', async () => {
    const result = await run({
      candidates: [candidate({ patch: '', reason: 'the analysis limit was reached' })],
      answers: ['view', 'skip'],
    });

    expect(result.out).toContain('no patch was produced: the analysis limit was reached');
    // The wording for a patch that exists but cannot be used would send the
    // developer looking for text that was never written.
    expect(result.out).not.toContain('the patch could not be used');
  });

  it('can still be fixed by hand, starting from an empty patch', async () => {
    const result = await run({
      candidates: [candidate({ patch: '', reason: 'the analysis limit was reached' })],
      answers: ['edit', 'apply'],
      edit: () => ({ ok: true, text: EDITED_PATCH }),
    });

    // The editor opens empty, and what comes back is validated the same way any
    // other edit is — the manual escape hatch is not a hole in the guarantees.
    expect(result.edited).toEqual(['']);
    expect(result.applied[0]?.patch.text).toBe(EDITED_PATCH);
    expect(result.summary.reviewed[0]?.outcome).toBe('applied');
  });

  it('prefers the pipeline`s reason over the parser`s only when there is one', async () => {
    // A patch the pipeline DID produce that happens to be unparseable: the reason
    // has to come from the parse failure, because the pipeline has nothing to say.
    const result = await run({
      candidates: [candidate({ patch: 'no patch here' })],
      answers: ['skip'],
    });

    expect(result.summary.reviewed[0]?.reason).toContain('no hunk header');
  });

  it('can be rescued by writing one by hand', async () => {
    const result = await run({
      candidates: [candidate({ patch: 'no patch' })],
      answers: ['edit', 'apply'],
      edit: () => ({ ok: true, text: EDITED_PATCH }),
    });

    // The editor is handed the raw text when there is nothing usable to repair,
    // so the developer starts from what the model said rather than an empty file.
    expect(result.edited).toEqual(['no patch']);
    expect(result.applied).toHaveLength(1);
    expect(result.applied[0]?.patch.text).toBe(EDITED_PATCH);
    expect(result.summary.reviewed[0]?.outcome).toBe('applied');
  });

  it('hands the REPAIRED patch to the editor, never the model`s raw text', async () => {
    // The whole reason [e]dit exists after parse-and-repair: making a human fix
    // the model's formatting would defeat the point of having repair logic.
    const result = await run({
      candidates: [candidate({ patch: DEFECTIVE_PATCH })],
      answers: ['edit', 'skip'],
      edit: () => ({ ok: false, reason: 'scripted stop' }),
    });

    expect(result.edited).toHaveLength(1);
    const handedOver = result.edited[0] ?? '';
    expect(handedOver).toContain('--- a/src/math.js');
    expect(handedOver).toContain('@@ -11,2 +11,1 @@');
    // And not the defective counting the model wrote.
    expect(handedOver).not.toContain('@@ -11,2 +11,2 @@');
  });
});

describe('reviewPatches — the loop across findings', () => {
  it('reviews every candidate in order, whatever each one decides', async () => {
    const result = await run({
      candidates: [
        candidate({ file: 'a.js', line: 1 }),
        candidate({ file: 'b.js', line: 2, patch: 'not a patch' }),
        candidate({ file: 'c.js', line: 3 }),
      ],
      answers: ['apply', 'skip', 'skip'],
    });

    expect(result.summary.reviewed.map((entry) => entry.file)).toEqual(['a.js', 'b.js', 'c.js']);
    expect(result.summary.reviewed.map((entry) => entry.outcome)).toEqual([
      'applied',
      'unusable',
      'skipped',
    ]);
    expect(result.summary.appliedFiles).toEqual(['a.js']);
  });

  it('does nothing at all when there is nothing to review', async () => {
    const result = await run({ candidates: [], answers: [] });

    expect(result.summary.reviewed).toEqual([]);
    expect(result.out).toBe('');
    expect(result.err).toBe('');
  });
});
