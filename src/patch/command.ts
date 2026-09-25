/**
 * `codeguard patch` — the review, apply, stage, re-scan flow (FR-7, PRD §10.1).
 *
 * ─── The shape of the command ────────────────────────────────────────────────
 *   scan (or read .codeguard/report.json)
 *     → review each suggested patch: [a]pply / [e]dit / [s]kip / [v]iew
 *     → stage what was applied
 *     → re-scan the staged diff and report the gate's actual verdict
 *
 * ─── Why it re-scans instead of assuming ─────────────────────────────────────
 * The pre-commit gate reads the INDEX, and the verdict the developer is about to
 * be held to belongs to the code that is staged NOW, not to the code that was
 * staged before they applied three patches. Announcing "fixed" on the strength
 * of patches that were accepted is exactly the failure mode a security tool
 * cannot afford: the patch may not have addressed the finding, the model may
 * have fixed one hunk of three, or the edit may have introduced something new.
 * So the answer comes from running the check again, and it is the check's exit
 * code that this command returns.
 *
 * ─── Why it is interactive-only ──────────────────────────────────────────────
 * Q2 of the Phase 5 decisions: this flow is `codeguard patch` and never the
 * pre-commit hook. A hook that stops to ask a question blocks CI, editor
 * integrations and scripted commits, and the answer to a prompt nobody can
 * answer is not "apply the model's patches".
 */

import { EXIT } from '../exit-codes';
import { findRepoRoot, stageFiles } from '../git/repo';
import { runPreCommitCheck, type ScanIo } from '../hooks/pre-commit';
import type { Finding } from '../engine/findings';
import type { Environment } from '../engine/mode';
import type { DeepAnalysis, LlmClient } from '../engine/remote';
import { readReport } from '../report/file';
import { plural, wrap, type EngineName } from '../report/render';
import { applyPatchToFile, type ApplyRequest, type ApplyResult } from './apply';
import {
  reviewPatches,
  type AskFn,
  type EditFn,
  type PatchCandidate,
  type ReviewSummary,
} from './review';

export interface PatchCommandOptions extends ScanIo {
  /** Directory the command was invoked from. Defaults to the process cwd. */
  cwd?: string;
  /** Force Local Mode for the scan and the re-scan. */
  local?: boolean;
  /** Force Remote Mode (an error, not a fallback, without a key). */
  remote?: boolean;
  /** Reuse `.codeguard/report.json` instead of scanning again. */
  fromReport?: boolean;
  /**
   * The interactive seams. Production leaves these undefined and gets inquirer
   * and the real editor; tests inject them so no test opens a TTY, an editor,
   * or the network.
   */
  ask?: AskFn;
  edit?: EditFn;
  apply?: (request: ApplyRequest) => Promise<ApplyResult>;
  /** Passed through to the scans. Tests only; production reads the repository. */
  environment?: Environment;
  client?: LlmClient;
}

/** inquirer's Ctrl-C. A person leaving a prompt is not a crash. */
function isInterrupt(error: unknown): boolean {
  return error instanceof Error && (error.name === 'ExitPromptError' || error.name === 'AbortPromptError');
}

/**
 * The reason given when the pipeline produced no patch and recorded nothing more
 * specific about this particular finding.
 *
 * It names the causes rather than picking one, because at this level all of them
 * are equally possible and inventing the wrong one would be worse than saying
 * nothing: the developer would go looking for a discarded answer that never
 * existed. The scan's own notes above say which one it actually was.
 */
const NO_PATCH_REASON =
  'deep analysis did not produce a patch for this finding — its answer was discarded or ' +
  'unusable, the analysis limit was reached, or the finding could not be matched to a hunk';

/**
 * Builds the review list: one candidate per finding the scan produced, each
 * carrying either the patch the pipeline drafted or the reason it drafted none.
 *
 * ─── Why findings without a patch are in here at all ─────────────────────────
 * They used to be dropped. This function kept only analyses that had patch text,
 * so a finding whose deep-analysis answer was discarded never reached the review
 * loop at all: the developer saw "no patches to review" for a commit the scan had
 * just called Critical, with nothing to distinguish an expected outcome from a
 * broken run. A finding with no patch is still a finding they have to deal with,
 * and it is shown here with the reason attached.
 *
 * Candidates with something to apply come first, and the ones that will have to
 * be fixed by hand come last — a review that opens with a run of refusals reads
 * as a broken command even when every one of them is explained.
 *
 * Local Mode contributes findings but never "no patch" reasons: it has no deep
 * analysis to explain, and PRD §5.2 makes it detection-only by design. Its
 * findings are left to the caller's own Local-Mode message.
 */
function candidatesFrom(
  engine: EngineName,
  findings: readonly Finding[],
  analyses: readonly DeepAnalysis[],
): PatchCandidate[] {
  const withPatches: PatchCandidate[] = [];
  const withoutPatches: PatchCandidate[] = [];

  for (const analysis of analyses) {
    const candidate: PatchCandidate = {
      file: analysis.file,
      line: analysis.line,
      severity: analysis.severity,
      category: analysis.category,
      explanation: analysis.explanation,
      patch: analysis.patch,
    };
    if (analysis.patch.trim() !== '') {
      withPatches.push(candidate);
    } else {
      // Withheld: the patch quoted a value CodeGuard redacted before sending, so
      // it was kept out of the report rather than shown and copied. The analysis
      // carries the sentence explaining that, and it belongs in front of the
      // developer rather than in a field nobody reads.
      withoutPatches.push({ ...candidate, reason: analysis.withheld ?? NO_PATCH_REASON });
    }
  }

  if (engine === 'remote') {
    // Matched by FILE, and deliberately conservative: an analysis covers a hunk,
    // the hunks are not reconstructable here, and a finding in a file that has
    // any analysis is assumed to be covered by it. Claiming "no patch exists"
    // for a finding that has one would be the worse error of the two.
    const analysed = new Set(analyses.map((analysis) => analysis.file));
    for (const finding of findings) {
      if (analysed.has(finding.file)) continue;
      withoutPatches.push({
        file: finding.file,
        line: finding.line,
        severity: finding.severity,
        category: finding.category,
        explanation: finding.message,
        patch: '',
        reason: NO_PATCH_REASON,
      });
    }
  }

  return [...withPatches, ...withoutPatches];
}

/**
 * Names the findings that have nothing to apply, before the review starts.
 *
 * Stated once, in the plural, rather than left to be inferred from a prompt that
 * offers [e] and [s] and no reason why. This is the difference between "the AI
 * did not manage to fix these" and "something is wrong with CodeGuard".
 */
function announceWithoutPatch(candidates: readonly PatchCandidate[], write: (text: string) => void): void {
  const missing = candidates.filter((candidate) => candidate.patch.trim() === '');
  if (missing.length === 0) return;

  write(
    `CodeGuard: ${plural(missing.length, 'finding')} came back with no patch — fix ${missing.length === 1 ? 'it' : 'them'} ` +
      'by hand, or press [e] at the prompt to write a patch yourself:\n',
  );
  for (const candidate of missing) {
    write(`  ${candidate.file}:${candidate.line}  ${candidate.severity} · ${candidate.category}\n`);
    write(`${wrap(`· ${candidate.reason ?? NO_PATCH_REASON}`, '    ', 72)}\n`);
  }
  write('\n');
}

/**
 * Runs the review flow and returns the process exit code.
 *
 * Never throws: an operational failure is reported and turned into EXIT.ERROR,
 * the way the rest of the CLI behaves.
 */
export async function runPatchCommand(options: PatchCommandOptions = {}): Promise<number> {
  const write = options.write ?? ((text: string) => void process.stdout.write(text));
  const writeError = options.writeError ?? ((text: string) => void process.stderr.write(text));
  const cwd = options.cwd ?? process.cwd();

  const repoRoot = await findRepoRoot(cwd);
  if (repoRoot === null) {
    writeError('CodeGuard: not inside a Git repository — there is nothing to patch.\n');
    return EXIT.ERROR;
  }

  // Refused rather than allowed to fail confusingly later. inquirer on a
  // non-TTY is a hang in CI and a stack trace under a pipe, and neither says
  // what the developer should do instead.
  if (options.ask === undefined && (process.stdin.isTTY !== true || process.stdout.isTTY !== true)) {
    writeError(
      'CodeGuard: `patch` is an interactive command and needs a terminal.\n' +
        '  Run it directly, or use `codeguard scan --remote` for a non-interactive report.\n',
    );
    return EXIT.ERROR;
  }

  const scanOptions = {
    ...options,
    cwd,
    ...(options.local === undefined ? {} : { local: options.local }),
    ...(options.remote === undefined ? {} : { remote: options.remote }),
  };

  // ─── Where the candidates come from ────────────────────────────────────────
  let candidates: PatchCandidate[];
  let baseline: number;
  let rescan = true;

  if (options.fromReport === true) {
    const loaded = await readReport(repoRoot);
    if (!loaded.ok) {
      writeError(`CodeGuard: ${loaded.reason}\n`);
      return EXIT.ERROR;
    }

    candidates = candidatesFrom(loaded.report.engine, loaded.report.findings, loaded.report.analyses);

    if (candidates.length === 0 && loaded.report.engine === 'local') {
      write(
        `CodeGuard: ${loaded.path} was written by Local Mode, which is detection-only (PRD §5.2) — ` +
          'it never produces patches.\n',
      );
      return EXIT.OK;
    }

    // The timestamp is shown because this path can act on a scan from hours or
    // days ago, and "these patches are for a different version of the file"
    // is worth being able to see before the applier refuses them one by one.
    write(
      `CodeGuard: reviewing ${plural(candidates.length, 'suggested patch', 'suggested patches')} from ` +
        `${loaded.path} (written ${loaded.report.generatedAt || 'at an unknown time'}).\n`,
    );
    // A re-scan is what the flag exists to avoid — `--from-report` means "use
    // what was already computed". The developer can run `codeguard scan` when
    // they want a fresh verdict.
    rescan = false;
    baseline = EXIT.OK;
  } else {
    const scan = await runPreCommitCheck(scanOptions);
    baseline = scan.exitCode;
    candidates = candidatesFrom(scan.engine, scan.findings, scan.analyses);

    if (candidates.length === 0) {
      if (scan.engine === 'local') {
        write(
          '\nCodeGuard: Local Mode is detection-only (PRD §5.2), so there are no patches to review.\n' +
            '  Set DEEPSEEK_API_KEY to have the AI engine draft fixes for these findings.\n',
        );
      } else {
        write('\nCodeGuard: no suggested patches to review — nothing above was left with a fix to offer.\n');
      }
      // The scan's own verdict stands: the developer still cannot commit, and
      // saying "nothing to do" with exit 0 would contradict the report above it.
      return baseline;
    }
  }

  write(
    `\nCodeGuard: ${plural(candidates.length, 'finding')} to review. ` +
      'Nothing is written until you accept it.\n\n',
  );
  announceWithoutPatch(candidates, write);

  // ─── Review ────────────────────────────────────────────────────────────────
  /**
   * The interactive binding is imported ON DEMAND, not at the top of the file.
   *
   * `prompt.ts` is the only module that imports inquirer, and inquirer 14 is a
   * pure-ESM package — importing it statically would mean `codeguard scan`,
   * which the pre-commit hook runs on every commit, resolving an entire ESM
   * dependency graph it has no use for, and taking on a `require(esm)`
   * compatibility requirement for a feature the scan path never touches.
   *
   * A dynamic import is preserved verbatim in this build's CommonJS output, so
   * the real ESM import happens at this line rather than at module load. The
   * `.js` extension is what TypeScript requires of an ESM specifier under
   * `nodenext`; it resolves against the compiled output.
   */
  const ask: AskFn =
    options.ask ??
    (await import('./prompt.js')).makeAsk({ useColor: options.useColor === true, writeError });
  // Wrapped rather than built eagerly: choosing [e]dit is the rare answer, and
  // building the editor binding up front would load it for every review.
  const edit: EditFn =
    options.edit ??
    (async (patch) =>
      (await import('./prompt.js')).makeEdit({ useColor: options.useColor === true, writeError })(patch));
  const applied: string[] = [];

  let summary: ReviewSummary | null = null;
  let interrupted = false;

  try {
    summary = await reviewPatches({
      candidates,
      repoRoot,
      write,
      writeError,
      ask,
      edit,
      ...(options.apply === undefined ? {} : { apply: options.apply }),
      onApplied: (file) => applied.push(file),
    });
  } catch (error) {
    if (!isInterrupt(error)) throw error;
    interrupted = true;
  }

  const reviewed = summary?.reviewed ?? [];

  // ─── Stage and re-check ────────────────────────────────────────────────────
  if (applied.length > 0) {
    await stageFiles(repoRoot, applied);
    write(`\nCodeGuard: staged ${plural(applied.length, 'changed file')} (${applied.join(', ')}).\n`);
  }

  if (interrupted) {
    write(
      'CodeGuard: review cancelled.\n' +
        (applied.length > 0
          ? '  The patches applied before you stopped are on disk and staged — check `git diff --cached`.\n'
          : '  Nothing was written.\n'),
    );
  } else {
    const appliedCount = reviewed.filter((entry) => entry.outcome === 'applied').length;
    const unusable = reviewed.filter((entry) => entry.outcome === 'unusable').length;
    write(
      `CodeGuard: reviewed ${plural(reviewed.length, 'finding')} — ` +
        `${appliedCount} applied, ${reviewed.length - appliedCount} left alone` +
        `${unusable > 0 ? ` (${unusable} had no usable patch)` : ''}.\n`,
    );
  }

  if (!rescan) {
    // No gate verdict exists on this path — the report was not a scan of the
    // current index — so the command reports what it did and hands the
    // verdict back to the tool that owns it rather than inventing one.
    if (applied.length > 0) {
      write('  Run `codeguard scan` to check the staged diff against the threshold.\n');
    }
    return baseline;
  }

  if (applied.length === 0) {
    // Nothing changed, so the gate's verdict cannot have changed either. Worth
    // skipping: a second remote scan costs a round trip and real money to
    // re-derive an answer the first scan already gave.
    if (!interrupted) {
      write(
        '\nCodeGuard: nothing was applied, so the verdict above still stands — ' +
          'the commit is still blocked.\n',
      );
    }
    return baseline;
  }

  write('\nCodeGuard: re-checking the staged diff...\n\n');
  const after = await runPreCommitCheck(scanOptions);

  if (baseline === EXIT.BLOCKED && after.exitCode === EXIT.OK) {
    write('\nCodeGuard: the staged changes are clean now — re-run `git commit` to proceed.\n');
  } else if (after.exitCode === EXIT.BLOCKED) {
    write('\nCodeGuard: the commit is still blocked by what is left above.\n');
  }

  return after.exitCode;
}
