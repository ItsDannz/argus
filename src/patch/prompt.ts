/**
 * The interactive binding for the review loop (FR-7).
 *
 * `review.ts` owns the decisions; this file owns the terminal. It is the only
 * place in the patch flow that imports `inquirer` (PRD §9.1), and it is kept
 * small on purpose: everything it does is turn a {@link ReviewQuestion} into
 * words and a keystroke back into a {@link ReviewChoice}, so the interesting
 * behaviour stays testable without a TTY.
 *
 * ─── Why the question is spelled out rather than just asked ──────────────────
 * The developer is being asked to write model-authored code to a file they are
 * about to commit. Answering that well needs the file, the line, the severity,
 * what the model claims is wrong, and whether the patch needed repair before it
 * could even be offered — which is why all of that is in the prompt and not
 * just in the report they scrolled past.
 */

import inquirer from 'inquirer';

import { wrap } from '../report/render';
import { editInEditor, resolveEditor, type EditOutcome, type EditorOptions } from './editor';
import type { AskFn, EditFn, ReviewChoice, ReviewQuestion } from './review';

const ANSI = { reset: '\u001b[0m', bold: '\u001b[1m', dim: '\u001b[2m' } as const;

/** Bounds the explanation, so one verbose finding cannot fill the screen. */
const EXPLANATION_WIDTH = 72;

export interface PromptOptions {
  useColor?: boolean;
  /** Where the "opened your editor" notice goes. */
  writeError: (text: string) => void;
  /** Injected by tests so no editor process is ever launched. */
  editor?: EditorOptions;
}

function paint(text: string, colour: string, useColor: boolean): string {
  return useColor ? `${colour}${text}${ANSI.reset}` : text;
}

/**
 * The question text: the finding first, then what the patch would do.
 *
 * The repairs are named here rather than only on stderr when they happen,
 * because by the time the developer is choosing they may no longer remember —
 * and "this patch was malformed and CodeGuard rewrote its header" is material
 * to whether they trust it.
 */
export function renderQuestion(question: ReviewQuestion, useColor = false): string {
  const { candidate, edited, repairs, canApply } = question;
  const heading =
    `\n${paint(`${candidate.file}:${candidate.line}`, ANSI.bold, useColor)}  ` +
    `${candidate.severity} · ${candidate.category}`;
  const lines = [heading, wrap(candidate.explanation, '  ', EXPLANATION_WIDTH)];

  const hunks = candidate.patch.split('\n').filter((line) => line.startsWith('@@')).length;
  const status = edited
    ? 'your edited patch'
    : canApply
      ? `the model's patch — ${hunks === 1 ? '1 hunk' : `${hunks} hunks`}`
      : 'no usable patch';
  lines.push(`  ${paint(`patch: ${status}`, ANSI.dim, useColor)}`);

  // When the pipeline produced nothing, the cause is spelled out under the
  // status line. Without it the developer is choosing between [e] and [s] on the
  // strength of "no usable patch", which does not distinguish a model that
  // declined to patch from one whose answer CodeGuard threw away.
  if (!canApply && !edited && candidate.reason !== undefined) {
    lines.push(wrap(`· no patch produced: ${candidate.reason}`, '  ', EXPLANATION_WIDTH));
  }

  for (const repair of repairs) {
    lines.push(wrap(`· repaired: ${repair}`, '  ', EXPLANATION_WIDTH));
  }

  return lines.join('\n');
}

/**
 * The four options, in the order the PRD names them.
 *
 * Selection is arrow keys and Enter — inquirer's list does not take single-key
 * shortcuts — so the letters are kept in the labels. `[a]pply` reading as a
 * shortcut that does nothing would be worse than not showing it at all, hence
 * the labels describe the action and the letters are decoration on the thing
 * the PRD asked for.
 */
function choicesFor(
  question: ReviewQuestion,
  editor: string,
): Array<{ name: string; value: ReviewChoice }> {
  const choices: Array<{ name: string; value: ReviewChoice }> = [];
  if (question.canApply) {
    choices.push({ name: `[a] apply it to ${question.candidate.file}`, value: 'apply' });
  }
  choices.push(
    {
      name: question.canApply ? `[e] edit the patch in ${editor}` : `[e] write a patch in ${editor}`,
      value: 'edit',
    },
    { name: '[s] skip this finding', value: 'skip' },
    { name: '[v] view the patch', value: 'view' },
  );
  return choices;
}

/** The inquirer-backed {@link AskFn}. */
export function makeAsk(options: PromptOptions): AskFn {
  const useColor = options.useColor === true;
  const editor = resolveEditor(options.editor?.env, options.editor?.platform);

  return async (question) => {
    const answers = await inquirer.prompt<{ choice: ReviewChoice }>([
      {
        // 'select', not the older 'list' — inquirer 14 renamed the arrow-key
        // selection prompt, and 'select' is what its own types accept.
        type: 'select',
        name: 'choice',
        message: renderQuestion(question, useColor),
        choices: choicesFor(question, editor),
        // Four options plus the question fit without scrolling.
        pageSize: 4,
      },
    ]);
    return answers.choice;
  };
}

/**
 * The editor-backed {@link EditFn}.
 *
 * Says which editor it is about to open and how to back out, because an editor
 * appearing full of diff is disorienting if you did not expect it — and because
 * "save and exit" is not obvious when the file may be unchanged on save.
 */
export function makeEdit(options: PromptOptions): EditFn {
  const editor = resolveEditor(options.editor?.env, options.editor?.platform);

  return async (patch: string): Promise<EditOutcome> => {
    options.writeError(
      `CodeGuard: opening ${editor} on the patch. Save and exit to continue, or empty the file to abandon the edit.\n`,
    );
    return editInEditor(patch, options.editor ?? {});
  };
}
