/**
 * Remote AI Mode — the two-stage pipeline (PRD §6.1, §9.2; FR-3..FR-6).
 *
 *   Stage 1  one request, reasoning OFF, over the whole diff
 *            → `ScanFinding[]`: which hunks deserve a closer look
 *   Stage 2  one request per flagged hunk, reasoning ON
 *            → `PatchSuggestion`: confirm or reject, explain, and patch
 *
 * The split is the cost design, not an architectural flourish. Stage 2 is the
 * expensive call, and it only ever runs on hunks Stage 1 already flagged — so the
 * cost of a scan scales with how much of the diff looks suspicious, not with how
 * big the diff is.
 *
 * ─── What this module is responsible for ─────────────────────────────────────
 * Ordering, redaction, budget, the cap, and assembling an honest result. It does
 * no prompt authoring (prompts/security-agent-prompts.ts), no HTTP
 * (remote/client.ts), no line arithmetic (remote/context.ts), and no output
 * shaping (report/render.ts). That separation is what lets the whole pipeline be
 * tested against a stub client with no network.
 *
 * ─── Which answer wins ───────────────────────────────────────────────────────
 * Between the model's two stages: Stage 1 over-reports by design, being one cheap
 * pass over everything and told to flag anything that might be a problem. Stage 2
 * exists to overrule it. So where Stage 2 answers about a hunk, its answer
 * REPLACES Stage 1's findings for that hunk — including when that answer is "no,
 * this is fine", which is the whole point of paying for a second call. Where
 * Stage 2 never answered, Stage 1's finding stands on its own and still counts
 * towards the commit threshold. Every one of those fallbacks is recorded in
 * `notAnalysed` so the report can say which findings arrived without a patch.
 *
 * Between the model and the rule engine there is no such competition, and that
 * asymmetry is deliberate. The model's judgement replaces the model's own earlier
 * judgement; it does not get to undercut a deterministic one. `options.baseline`
 * carries the rule engine's result for the same diff, and `reconcile` floors the
 * final severities on it — raising, adding, and overruling dismissals, never
 * lowering. The reason is in engine/reconcile.ts: which engine is configured must
 * not decide whether a known-bad commit is stopped.
 *
 * ─── Failure policy ──────────────────────────────────────────────────────────
 * Stage 1 failing is fatal to Remote Mode: the caller falls back to Local
 * (PRD §6.3). Without triage there is nothing at all to report, so there is no
 * partial result worth salvaging.
 *
 * Stage 2 failing is NOT. The first failure stops the loop — a provider that just
 * failed is likely to fail again, and grinding through the remaining hunks would
 * spend the cap on timeouts — but the findings already gathered are kept. Every
 * hunk still waiting is reported from triage, without a patch. Degrading all the
 * way to Local would throw away real results to punish a partial outage.
 *
 * One failure is excepted from that, and retried once: a well-formed answer with
 * no content in it. It costs a request, and the alternative is losing the patch
 * that is the entire reason Stage 2 exists — see `isEmptyAnswer`, which also says
 * why the other kinds are not retried.
 */

import type { Category, PatchSuggestion, ScanFinding, Severity } from '../../prompts/security-agent-prompts';
import {
  buildPatchUserPrompt,
  buildScanUserPrompt,
  PATCH_SYSTEM_PROMPT,
  SCAN_SYSTEM_PROMPT,
} from '../../prompts/security-agent-prompts';
import type { Finding } from '../findings';
import { reconcileWithBaseline } from '../reconcile';
import { filterExcludedFiles, truncateToBudget } from './budget';
import { createDeepSeekClient, LlmError, type LlmClient } from './client';
import { selectFlaggedHunks } from './context';
import { parsePatchResponse, parseTriageResponse } from './parse';
import { containsPlaceholder, redactDiff, type Redaction } from './redact';

export type { LlmClient } from './client';
export { LlmError } from './client';
export { redactDiff } from './redact';

/** A hunk that reached Stage 2, and whatever came back. */
export interface DeepAnalysis {
  file: string;
  line: number;
  severity: Severity;
  category: Category;
  explanation: string;
  /** Unified diff, or '' when there is nothing applicable. */
  patch: string;
  confidence: PatchSuggestion['confidence'];
  /** Why `patch` is empty, when it is. Null when a patch is present. */
  withheld: string | null;
  /** The transmitted hunk contained a redacted value. */
  redacted: boolean;
}

export interface RemoteScanOutcome {
  /** Findings that count towards the commit threshold. */
  findings: Finding[];
  /** Deep-analysed and rejected as false positives. Reported, never counted. */
  dismissed: Finding[];
  /**
   * The subset of `findings` that counts without a patch attached, for any
   * reason — beyond the cap, deep analysis failed, the finding named a hunk that
   * does not exist, or the rule engine reported it and triage did not. Listed so
   * the report can group them; not a separate set of problems.
   */
  notAnalysed: Finding[];
  /** One entry per hunk that reached Stage 2 and produced a usable answer. */
  analyses: DeepAnalysis[];
  redactions: Redaction[];
  /** Everything the user needs to know about what was skipped or truncated. */
  notes: string[];
  /** Requests actually made, so the cost of a scan can be stated plainly. */
  requestCount: number;
}

/**
 * The two knobs this pipeline actually reads.
 *
 * Deliberately narrower than the `remote` block in the config file. `hookMode`
 * lives in that block too, but it decides WHICH ENGINE RUNS — a question already
 * settled by the time this code is reached. Accepting the whole block would let
 * the pipeline believe it has a say in that decision, and the first reader to
 * see the field here would reasonably conclude it does.
 */
export interface RemoteBudget {
  maxDeepAnalysisHunks: number;
  timeoutMs: number;
}

export interface RemoteScanOptions {
  /** Raw staged diff, unredacted. Redaction happens inside, always. */
  diff: string;
  /** `baseUrl` is set only when `CODEGUARD_BASE_URL` overrides the endpoint. */
  credentials: { apiKey: string; model: string; baseUrl?: string };
  remote: RemoteBudget;
  /** `excludePaths` from the config; excluded files are never transmitted. */
  exclude?: (filePath: string) => boolean;
  /**
   * The deterministic rule-engine result for the same diff — Remote Mode's floor.
   *
   * Stage 2 is a probabilistic judgement, and on its own it was allowed to come
   * out BELOW what a regex match had already established for a class of bug with
   * an unambiguous signature: a critical SQL injection triaged as High, which
   * warns instead of blocking. Passing the baseline in lets `reconcile` raise a
   * severity to the rule engine's, add what the rules found and the model did
   * not, and overrule a deep-analysis dismissal of a confident rule match. See
   * engine/reconcile.ts for the policy and its limits.
   *
   * Taken as data rather than run here so this module still knows nothing about
   * the Local engine, and so the caller can run the rules once and reuse the
   * result if it has to fall back to Local Mode.
   */
  baseline?: readonly Finding[];
  /** Injectable for tests. Defaults to the live DeepSeek client. */
  client?: LlmClient;
  /** Progress feedback (NFR: "visible progress feedback"). Goes to stderr. */
  onProgress?: (message: string) => void;
  /** Cancels in-flight requests. Per-request timeouts are applied on top. */
  signal?: AbortSignal;
}

/** Converts a model finding into the shape the threshold and renderer use. */
function toFinding(finding: ScanFinding): Finding {
  return {
    file: finding.file,
    line: finding.line_range[0],
    category: finding.category,
    // The category stands in for a rule id here. See engine/findings.ts.
    ruleId: finding.category,
    severity: finding.severity,
    message: finding.summary,
  };
}

/**
 * The one provider failure worth repeating: an empty but well-formed answer.
 *
 * Observed live, which is why it is here at all. Deep analysis of a hunk came
 * back as `provider returned nothing usable`, the scan degraded to triage-only
 * findings as designed — and the identical call had succeeded minutes earlier on
 * the identical input. Nothing about the request, the credential or the endpoint
 * had changed, so asking again was worth one request. The thing being bought is
 * the patch, and the patch is the whole value of Stage 2.
 *
 * Deliberately not the other three kinds. A transport failure and a non-2xx are
 * statements about reachability or about the request itself; repeating an
 * unreachable call spends the timeout twice to reach the same conclusion, and
 * repeating a request the provider just rejected gets the same rejection. Those
 * deserve the caller's fallback, not a second attempt.
 */
function isEmptyAnswer(error: unknown): boolean {
  return error instanceof LlmError && error.kind === 'empty';
}

/**
 * Combines the caller's signal with a per-request timeout.
 *
 * Both are needed and they are not alternatives: the timeout bounds ONE slow
 * request, and the external signal lets a caller abandon a scan already in
 * progress. `AbortSignal.any` fires when either does.
 */
function requestSignal(external: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return external === undefined ? timeout : AbortSignal.any([external, timeout]);
}

/**
 * The paths present in a diff, in the form the model was asked to quote them.
 *
 * Read back out of the text we actually transmitted, so an excluded file — which
 * never reached the API — can never be named by a finding we accept.
 */
function pathsIn(diff: string): Set<string> {
  const paths = new Set<string>();
  for (const line of diff.split('\n')) {
    if (!line.startsWith('+++ ')) continue;
    const named = line.slice(4).trim().replace(/^[ab]\//, '');
    if (named !== '/dev/null' && named !== '') paths.add(named);
  }
  return paths;
}

/**
 * Runs the two-stage scan.
 *
 * @throws {LlmError} when Stage 1 could not be completed, or when triage came
 *         back as something that is not JSON at all. The caller treats this as
 *         the trigger to fall back to Local Mode (PRD §6.3).
 */
export async function runRemoteScan(options: RemoteScanOptions): Promise<RemoteScanOutcome> {
  const notes: string[] = [];
  const analyses: DeepAnalysis[] = [];
  const dismissed: Finding[] = [];
  const counted: Finding[] = [];
  const notAnalysed: Finding[] = [];
  let requestCount = 0;
  // Dismissals are recorded per hunk (that is what Stage 2 reasons about), but
  // reported per Stage-1 finding, so the count matches what triage produced.
  let clearedFindings = 0;

  const progress = options.onProgress ?? ((): void => {});
  const client =
    options.client ??
    createDeepSeekClient({
      apiKey: options.credentials.apiKey,
      model: options.credentials.model,
      ...(options.credentials.baseUrl === undefined ? {} : { baseUrl: options.credentials.baseUrl }),
    });

  const short = (findings: readonly ScanFinding[]): void => {
    for (const finding of findings) {
      const entry = toFinding(finding);
      counted.push(entry);
      notAnalysed.push(entry);
    }
  };

  // --- Prepare the payload --------------------------------------------------
  // Order matters. Exclude first, so code from an excluded path is never
  // redacted, transmitted, or reasoned about. Redact second, so the budget is
  // measured against what actually goes over the wire.
  const filtered = filterExcludedFiles(options.diff, options.exclude ?? (() => false));
  if (filtered.excluded.length > 0) {
    notes.push(`Excluded by configuration, not sent to the API: ${filtered.excluded.join(', ')}.`);
  }

  const { diff: redacted, redactions } = redactDiff(filtered.diff);
  if (redactions.length > 0) {
    const files = [...new Set(redactions.map((entry) => entry.file).filter((name) => name !== ''))];
    notes.push(
      `Redacted ${redactions.length} secret-like ${redactions.length === 1 ? 'value' : 'values'} ` +
        `before transmission${files.length > 0 ? ` (${files.join(', ')})` : ''}. The values were not sent.`,
    );
  }

  const budgeted = truncateToBudget(redacted);
  if (budgeted.omitted.length > 0) {
    notes.push(
      `The diff exceeded the triage budget, so these files were NOT analysed at all: ${budgeted.omitted.join(', ')}.`,
    );
  }

  /**
   * Assembles the result, applying the rule engine's floor on the way out.
   *
   * Every exit from this function goes through here, including the one below for
   * a diff that fitted no budget — that path made no request, but the rules ran
   * anyway, and "nothing fitted the budget" must not be able to mean "nothing
   * found" when the deterministic engine found something.
   */
  const finish = (): RemoteScanOutcome => {
    const reconciled = reconcileWithBaseline({
      counted,
      dismissed,
      baseline: options.baseline ?? [],
    });
    for (const note of reconciled.notes) notes.push(note);

    // A reinstated finding never reached Stage 2, so it is unpatched for the same
    // reason a capped or unmatched one is.
    for (const finding of reconciled.reinstated) notAnalysed.push(finding);

    return {
      findings: reconciled.counted,
      dismissed: reconciled.dismissed,
      notAnalysed,
      analyses,
      redactions,
      notes,
      requestCount,
    };
  };

  if (budgeted.empty) {
    notes.push('Nothing in the diff fitted the triage budget, so no request was made.');
    return finish();
  }

  // --- Stage 1: triage ------------------------------------------------------
  progress(`CodeGuard: triaging the diff with ${client.model} (reasoning off)…`);
  requestCount += 1;
  const triageText = await client.complete(
    {
      system: SCAN_SYSTEM_PROMPT,
      user: buildScanUserPrompt(budgeted.diff),
      reasoning: false,
    },
    requestSignal(options.signal, options.remote.timeoutMs),
  );

  // Computed once: it is the set of paths the model was shown, and it does not
  // change between Stage 1 and Stage 2.
  const knownFiles = pathsIn(budgeted.diff);

  const triage = parseTriageResponse(triageText, { knownFiles });
  for (const reason of triage.rejected) notes.push(`Discarded a triage entry: ${reason}`);
  progress(
    `CodeGuard: triage flagged ${triage.value.length} ${triage.value.length === 1 ? 'issue' : 'issues'}.`,
  );

  // --- Stage 2: deep analysis ----------------------------------------------
  const selection = selectFlaggedHunks(
    budgeted.diff,
    triage.value,
    options.remote.maxDeepAnalysisHunks,
  );

  if (selection.unmatched.length > 0) {
    const files = [...new Set(selection.unmatched.map((finding) => finding.file))];
    notes.push(
      `${selection.unmatched.length} triage ${selection.unmatched.length === 1 ? 'finding' : 'findings'} ` +
        `could not be matched to a hunk in the diff (${files.join(', ')}), so ` +
        `${selection.unmatched.length === 1 ? 'it was' : 'they were'} reported without a patch.`,
    );
    short(selection.unmatched);
  }

  if (selection.beyondCap.length > 0) {
    const files = [...new Set(selection.beyondCap.map((hunk) => hunk.file))];
    const limit = options.remote.maxDeepAnalysisHunks;
    notes.push(
      `Reached the limit of ${limit} deep-analysis ${limit === 1 ? 'hunk' : 'hunks'}; ` +
        `${selection.beyondCap.length} more ${selection.beyondCap.length === 1 ? 'hunk was' : 'hunks were'} ` +
        `reported without a patch (${files.join(', ')}). Raise remote.maxDeepAnalysisHunks to cover them.`,
    );
    for (const hunk of selection.beyondCap) short(hunk.findings);
  }

  /**
   * One Stage-2 request, with a single retry for an empty answer.
   *
   * Bounded to one on purpose. Two identical empty answers in a row is a pattern
   * rather than a hiccup, and the caller already knows what to do with it — keep
   * the findings already gathered and report the rest without patches. Further
   * attempts would only delay that.
   *
   * The signal is rebuilt for the retry: `AbortSignal.timeout` starts counting
   * when it is created, so reusing the first one would hand the second attempt
   * whatever little was left of the first attempt's budget.
   */
  const deepAnalyse = async (file: string, user: string): Promise<string> => {
    const request = { system: PATCH_SYSTEM_PROMPT, user, reasoning: true };
    const signal = (): AbortSignal => requestSignal(options.signal, options.remote.timeoutMs);

    requestCount += 1;
    try {
      return await client.complete(request, signal());
    } catch (error) {
      if (!isEmptyAnswer(error)) throw error;
      progress(`CodeGuard: deep analysis of ${file} came back empty; retrying it once.`);
      requestCount += 1;
      return await client.complete(request, signal());
    }
  };

  for (const [index, hunk] of selection.selected.entries()) {
    const headline = hunk.findings[0];
    const line = headline?.line_range[0] ?? 1;
    progress(
      `CodeGuard: analysing hunk ${index + 1}/${selection.selected.length} ` +
        `(${hunk.file}:${line}, reasoning on)…`,
    );

    let text: string;
    try {
      text = await deepAnalyse(
        hunk.file,
        buildPatchUserPrompt({
          file: hunk.file,
          flaggedSummary: headline?.summary ?? '',
          category: headline?.category ?? 'other',
          hunk: hunk.text,
          // No surrounding file content is passed, deliberately. FR-4 scopes
          // Remote Mode to the diff, and the only other source of context is
          // the working tree — sending code the developer did not stage is
          // exactly the exposure the diff-only rule exists to prevent. The
          // hunk already carries git's own three lines of context either side.
        }),
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      notes.push(
        `Deep analysis stopped after ${analyses.length} of ${selection.selected.length} hunks — ${message}. ` +
          'The remaining hunks are reported from triage alone, without patches.',
      );
      // This hunk and every one after it. `slice(index)` includes the failure.
      for (const remaining of selection.selected.slice(index)) short(remaining.findings);
      break;
    }

    let suggestion: PatchSuggestion | null;
    try {
      const parsed = parsePatchResponse(text, knownFiles);
      for (const reason of parsed.rejected) notes.push(`Discarded a deep-analysis entry: ${reason}`);
      suggestion = parsed.value;
    } catch (error) {
      // A non-JSON answer for one hunk is that hunk's problem, not the scan's.
      const message = error instanceof Error ? error.message : String(error);
      notes.push(`Deep analysis of ${hunk.file} returned something unusable — ${message}`);
      short(hunk.findings);
      continue;
    }

    if (suggestion === null) {
      short(hunk.findings);
      continue;
    }

    // Stage 2 was asked about ONE file. An answer naming a different one is not
    // an answer to that question, and accepting it would attribute a finding to
    // code the model was never shown — a `src/run.js` finding silently rewritten
    // as a `src/db.js` one, with a patch to match. `knownFiles` cannot catch
    // this, because the other file really is in the diff; only this comparison
    // can. The hunk keeps its Stage-1 finding and loses its patch.
    if (suggestion.file !== hunk.file) {
      notes.push(
        `Deep analysis of ${hunk.file} answered about ${suggestion.file} instead, so it was ` +
          `discarded and ${hunk.file} is reported without a patch.`,
      );
      short(hunk.findings);
      continue;
    }

    // An empty patch is the documented false-positive signal (PATCH_SYSTEM_PROMPT).
    // It is the one outcome that removes a finding from the count, and it is why
    // Stage 2 exists: Stage 1 flags anything that might be a problem, and a
    // finding that survives triage but not deep analysis is noise the threshold
    // should never see.
    if (suggestion.suggested_patch === '') {
      clearedFindings += hunk.findings.length;
      dismissed.push({
        file: suggestion.file,
        line,
        category: suggestion.category,
        ruleId: suggestion.category,
        severity: suggestion.severity,
        message: suggestion.explanation,
      });
      continue;
    }

    // The fail-safe for a patch that quotes a line we redacted. Applying it would
    // write `«REDACTED:...»` into the developer's file, so the patch text is
    // withheld from the report entirely rather than shown and left to be copied.
    // The explanation and severity survive, so the finding is still actionable —
    // just not automatically fixable.
    const withheld = containsPlaceholder(suggestion.suggested_patch)
      ? 'The suggested patch quotes a value that CodeGuard redacted before sending, so it cannot be applied. Fix this one by hand.'
      : null;

    analyses.push({
      file: suggestion.file,
      line,
      severity: suggestion.severity,
      category: suggestion.category,
      explanation: suggestion.explanation,
      patch: withheld === null ? suggestion.suggested_patch : '',
      confidence: suggestion.confidence,
      withheld,
      redacted: hunk.redacted,
    });

    counted.push({
      file: suggestion.file,
      line,
      category: suggestion.category,
      ruleId: suggestion.category,
      severity: suggestion.severity,
      message: suggestion.explanation,
    });
  }

  if (dismissed.length > 0) {
    const one = clearedFindings === 1;
    notes.push(
      `Deep analysis cleared ${clearedFindings} triage ${one ? 'finding' : 'findings'} as ` +
        `${one ? 'a false positive' : 'false positives'}; ${one ? 'it is' : 'they are'} shown below ` +
        'but do not count towards the threshold.',
    );
  }

  return finish();
}
