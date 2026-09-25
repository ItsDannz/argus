/**
 * The per-finding review loop (FR-7, PRD §10.1).
 *
 * One finding at a time, four options: [a]pply, [e]dit, [s]kip, [v]iew. The
 * loop is written here rather than inside the prompt library so that every
 * branch — what happens when an apply fails, when an edit comes back broken,
 * when the model's patch cannot be parsed at all — is testable without a
 * terminal, an editor, or a network.
 *
 * ─── The two rules this loop is built around ─────────────────────────────────
 * Nothing is written without an explicit [a]pply. Not a valid edit, not a
 * repaired patch, not the only finding in the scan. A developer who edits a
 * patch has told CodeGuard what the fix should be; they have not told it to
 * write it. An edit is a proposal until it is applied, which is also why an
 * edited patch is re-validated rather than trusted — the file on disk is at
 * stake, not the text in the editor.
 *
 * A failure returns to the prompt instead of ending the finding. An apply that
 * does not fit, or an edit that does not parse, leaves the developer with a
 * reason and the same four options. The alternative — dropping the finding,
 * or worse, discarding the edit — loses work that took a human to produce.
 */

import type { Category, Severity } from '../prompts/security-agent-prompts';
import { plural } from '../report/render';
import { applyPatchToFile, type ApplyRequest, type ApplyResult } from './apply';
import type { EditOutcome } from './editor';
import { adoptPatch, parseAndRepairPatch, type RepairedPatch } from './normalise';

/** A patch the pipeline produced, with the finding it belongs to. */
export interface PatchCandidate {
  file: string;
  line: number;
  severity: Severity;
  category: Category;
  /** The model's explanation, so the decision is not made from a file name. */
  explanation: string;
  /** `suggested_patch` exactly as the provider returned it. Empty when there is none. */
  patch: string;
  /**
   * Why the pipeline produced no patch for this finding.
   *
   * Absent when a patch was produced, and absent when the empty `patch` is the
   * developer's own doing (they emptied the file in the editor and abandoned the
   * edit) — those have their own reason by then. It matters because "this
   * finding has no patch" is not one fact but several: the deep-analysis answer
   * was discarded, the patch quoted a value CodeGuard had redacted, the analysis
   * limit was reached, the hunk could not be matched to the finding. A developer
   * told only that there is nothing to apply cannot tell a broken run from an
   * ordinary one, and this is the field that says which.
   */
  reason?: string;
}

export type ReviewChoice = 'apply' | 'edit' | 'skip' | 'view';

export interface ReviewQuestion {
  candidate: PatchCandidate;
  /** False when no usable patch could be built, which takes [a]pply off the menu. */
  canApply: boolean;
  /** True once the developer has edited it, so the prompt stops saying "the model's". */
  edited: boolean;
  /** What had to be repaired. Empty when the model's patch was well-formed. */
  repairs: readonly string[];
}

/** Asks one question. The interactive binding lives in prompt.ts. */
export type AskFn = (question: ReviewQuestion) => Promise<ReviewChoice>;

/** Opens the patch for editing. Returns the text the developer saved. */
export type EditFn = (patch: string) => Promise<EditOutcome>;

export type ReviewOutcome = 'applied' | 'skipped' | 'unusable';

export interface ReviewedCandidate {
  file: string;
  line: number;
  outcome: ReviewOutcome;
  /** Why the patch was unusable, when it was. */
  reason?: string;
}

export interface ReviewSummary {
  reviewed: ReviewedCandidate[];
  /** Files written, deduplicated, in the order they were first applied. */
  appliedFiles: string[];
}

export interface ReviewOptions {
  candidates: readonly PatchCandidate[];
  repoRoot: string;
  write: (text: string) => void;
  writeError: (text: string) => void;
  ask: AskFn;
  edit: EditFn;
  /** Injected by tests. Defaults to the real applier. */
  apply?: (request: ApplyRequest) => Promise<ApplyResult>;
  /**
   * Called the moment a file is written.
   *
   * The caller needs the list of modified files even when this loop does not
   * finish — Ctrl-C during review is an ordinary way to leave a prompt, and the
   * files applied before it are on disk either way. Reporting them only in the
   * return value would mean an interrupted review left the working tree edited
   * with nothing said about it.
   */
  onApplied?: (file: string) => void;
}

/** The patch, indented under its heading, for the [v]iew option. */
function view(candidate: PatchCandidate, text: string, edited: boolean): string {
  const heading =
    `  ${candidate.file}:${candidate.line}  ${candidate.severity} ${candidate.category}` +
    (edited ? '  (edited by you)' : '');
  return `${[heading, ...text.split('\n').map((line) => `    ${line}`)].join('\n')}\n`;
}

export async function reviewPatches(options: ReviewOptions): Promise<ReviewSummary> {
  const apply = options.apply ?? applyPatchToFile;
  const { write, writeError } = options;

  const reviewed: ReviewedCandidate[] = [];
  const appliedFiles: string[] = [];

  for (const candidate of options.candidates) {
    const first = parseAndRepairPatch(candidate.patch, candidate.file);
    let patch: RepairedPatch | null = first.ok ? first.patch : null;
    let repairs: readonly string[] = first.ok ? first.patch.repairs : [];
    // The candidate's own reason wins over the parser's: when the pipeline never
    // produced a patch, "the patch is empty" is a description of the symptom,
    // and the pipeline knows the cause.
    let unusableReason: string | null = first.ok ? null : (candidate.reason ?? first.reason);
    let edited = false;

    if (patch !== null && repairs.length > 0) {
      // Said out loud rather than fixed quietly. The developer is about to
      // review a patch the model wrote wrong, and a repair nobody mentioned is
      // exactly the kind of thing that erodes trust in a gate.
      writeError(
        `CodeGuard: repaired the patch for ${candidate.file}:${candidate.line} before offering it — ` +
          `${repairs.join('; ')}.\n`,
      );
    }

    for (;;) {
      const choice = await options.ask({
        candidate,
        canApply: patch !== null,
        edited,
        repairs,
      });

      if (choice === 'view') {
        if (patch === null && unusableReason !== null) {
          write(
            // "the patch could not be used" would be wrong for a finding the
            // pipeline never produced a patch for: there is no patch to look at,
            // and saying otherwise sends the developer hunting for text that
            // does not exist.
            candidate.patch.trim() === ''
              ? `  ${candidate.file}:${candidate.line} — no patch was produced: ${unusableReason}\n`
              : `  ${candidate.file}:${candidate.line} — the patch could not be used: ${unusableReason}\n`,
          );
        }
        write(view(candidate, patch?.text ?? candidate.patch, edited));
        continue;
      }

      if (choice === 'skip') {
        reviewed.push({
          file: candidate.file,
          line: candidate.line,
          outcome: patch === null ? 'unusable' : 'skipped',
          ...(unusableReason === null ? {} : { reason: unusableReason }),
        });
        break;
      }

      if (choice === 'edit') {
        // The repaired form is what gets edited, not the model's raw text — see
        // the header of normalise.ts. Making a human fix the model's formatting
        // would defeat the point of having repair logic at all.
        const outcome = await options.edit(patch?.text ?? candidate.patch);
        if (!outcome.ok) {
          writeError(`CodeGuard: ${outcome.reason}.\n`);
          continue;
        }

        const adopted = adoptPatch(outcome.text, candidate.file);
        if (!adopted.ok) {
          writeError(
            `CodeGuard: the edited patch is not usable — ${adopted.reason}\n` +
              '  Fix it and try again, or skip this finding.\n',
          );
          continue;
        }

        patch = adopted.patch;
        repairs = [];
        edited = true;
        unusableReason = null;
        continue;
      }

      // [a]pply. The asker is not offered this when there is no patch, and the
      // guard is here so a future caller cannot reach the applier without one.
      if (patch === null) continue;

      const result = await apply({ repoRoot: options.repoRoot, file: candidate.file, patch });
      if (!result.ok) {
        // Not a dead end: the reason is reported and the prompt comes back, so
        // the developer can edit the patch, skip it, or read it again.
        unusableReason = result.reason;
        writeError(`CodeGuard: could not apply the patch — ${result.reason}\n`);
        continue;
      }

      if (!appliedFiles.includes(candidate.file)) {
        appliedFiles.push(candidate.file);
        options.onApplied?.(candidate.file);
      }
      reviewed.push({ file: candidate.file, line: candidate.line, outcome: 'applied' });
      write(
        `CodeGuard: applied the patch to ${candidate.file} — ` +
          `${plural(result.changedLines.length, 'line')} changed.\n`,
      );
      break;
    }
  }

  return { reviewed, appliedFiles };
}
