/**
 * Maps Stage-1 findings back onto the hunks that produced them, and decides
 * which hunks are worth a Stage-2 call.
 *
 * This module is where the cost control actually bites. Stage 1 is one request
 * over the whole diff; Stage 2 is one reasoning request per flagged hunk, so the
 * set chosen here is the entire variable cost of a remote scan.
 *
 * The mapping runs against the REDACTED diff, because that is the text the model
 * saw and answered about. Redaction preserves line count (see redact.ts), so the
 * numbers line up with the original either way — but the hunk *text* sent
 * onward must be the redacted one, since that is what must never be un-redacted.
 */

import type { Severity, ScanFinding } from '../../prompts/security-agent-prompts';
import { SEVERITY_RANK } from '../../severity';
import { parseDiff, type DiffHunk } from '../diff';
import { containsPlaceholder } from './redact';

export interface FlaggedHunk {
  file: string;
  /** Unified-diff text of the hunk, as it appeared in what we transmitted. */
  text: string;
  /** Findings that landed on this hunk, worst first. Usually one. */
  findings: ScanFinding[];
  severity: Severity;
  /**
   * False when no hunk in the file covered the reported line and the nearest
   * one was used instead. Worth carrying: it means the model's line numbers and
   * ours disagree about this file, which makes the resulting patch less
   * trustworthy.
   */
  lineMatched: boolean;
  /**
   * True when the transmitted hunk contained a redaction placeholder.
   *
   * The consequence is handled in index.ts: a patch quoting a redacted line
   * would carry the placeholder, and applying it would write
   * `«REDACTED:...»` into the file.
   */
  redacted: boolean;
}

export interface HunkSelection {
  /** Hunks to deep-analyse, worst first. At most `limit` of them. */
  selected: FlaggedHunk[];
  /**
   * Flagged hunks that fell outside the cap. Returned in full rather than
   * counted, so the report can name the files that were not analysed. A cap
   * that truncates silently is worse than no cap: the developer would read a
   * partial result as complete.
   */
  beyondCap: FlaggedHunk[];
  /**
   * Findings that matched no file or hunk in the diff we sent.
   *
   * Both causes are real: the model named a path it invented, or it gave a line
   * number outside every hunk in a file it got right. Either way there is nothing
   * to reason about and no patch to generate — but the finding itself came from
   * a diff we really did send, so discarding it here would make the report
   * quieter than the scan actually was. The caller reports it without a patch.
   */
  unmatched: ScanFinding[];
}

/** Rebuilds the unified-diff text of a hunk from its parsed form. */
function renderHunk(hunk: DiffHunk): string {
  const marker = { add: '+', del: '-', context: ' ' } as const;
  // The "\ No newline at end of file" marker is dropped by the parser and is not
  // reconstructed here. It matters for byte-exact patch application, not for
  // showing a model the code, and Phase 5 applies patches through the `diff`
  // package rather than by re-parsing this text.
  return [hunk.header, ...hunk.lines.map((line) => `${marker[line.kind]}${line.content}`)].join('\n');
}

/** Distance from `line` to the hunk's new-side span, 0 when it falls inside. */
function distanceTo(hunk: DiffHunk, line: number): number {
  const start = hunk.newStart;
  // A hunk made only of deletions has an empty new-side span; `newStart` is then
  // the line after which the removal happened, which is the closest anchor.
  const end = hunk.newStart + Math.max(1, hunk.newCount) - 1;
  if (line < start) return start - line;
  if (line > end) return line - end;
  return 0;
}

/**
 * Chooses the hunks to deep-analyse.
 *
 * Ordering is by severity, then by diff order to keep it stable. Severity first
 * because the cap has to cut somewhere, and a Critical finding is worth a
 * reasoning call more than a Low one — a hunk carrying several findings takes
 * its worst.
 *
 * @param redactedDiff The diff that was transmitted to Stage 1.
 * @param findings Findings from Stage 1.
 * @param limit Maximum hunks to return in `selected`. Zero is valid: it means
 *              "triage only, never patch".
 */
export function selectFlaggedHunks(
  redactedDiff: string,
  findings: readonly ScanFinding[],
  limit: number,
): HunkSelection {
  const files = parseDiff(redactedDiff);
  const bySeverityThenOrder: FlaggedHunk[] = [];
  const index = new Map<string, FlaggedHunk>();
  const unmatched: ScanFinding[] = [];

  findings.forEach((finding, order) => {
    const file = files.find((entry) => entry.path === finding.file);
    if (file === undefined || file.hunks.length === 0) {
      // A binary file, a pure rename, or a path the model invented. Nothing to
      // send to Stage 2 — but the caller still reports it. See `unmatched`.
      unmatched.push(finding);
      return;
    }

    const target = finding.line_range[0];
    const exact = file.hunks.find((hunk) => distanceTo(hunk, target) === 0);
    const chosen =
      exact ?? file.hunks.reduce((best, hunk) => (distanceTo(hunk, target) < distanceTo(best, target) ? hunk : best));

    // One call per hunk, not one per finding: two findings on the same hunk are
    // the same code to reason about, and charging twice for it would make the
    // cap lie about how much of the diff was covered.
    const key = `${finding.file}:${chosen.header}:${chosen.newStart}`;
    const existing = index.get(key);
    if (existing !== undefined) {
      existing.findings.push(finding);
      if (SEVERITY_RANK[finding.severity] > SEVERITY_RANK[existing.severity]) {
        existing.severity = finding.severity;
      }
      existing.redacted ||= containsPlaceholder(renderHunk(chosen));
      return;
    }

    const text = renderHunk(chosen);
    const entry: FlaggedHunk = {
      file: finding.file,
      text,
      findings: [finding],
      severity: finding.severity,
      lineMatched: exact !== undefined,
      redacted: containsPlaceholder(text),
    };
    index.set(key, entry);
    bySeverityThenOrder.push(entry);
  });

  const ordered = bySeverityThenOrder
    .map((entry, order) => ({ entry, order }))
    .sort(
      (a, b) =>
        SEVERITY_RANK[b.entry.severity] - SEVERITY_RANK[a.entry.severity] || a.order - b.order,
    )
    .map((pair) => pair.entry);

  return {
    selected: ordered.slice(0, Math.max(0, limit)),
    beyondCap: ordered.slice(Math.max(0, limit)),
    unmatched,
  };
}
