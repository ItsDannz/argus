/**
 * Turns a list of findings plus a configured threshold into a block/warn
 * decision (FR-9, PRD §10.1 step 5).
 *
 * Kept separate from both the scanner and the hook so the policy can be tested
 * exhaustively without a repository, a diff, or any I/O. The hook's job is then
 * only "print this and turn it into an exit code".
 */

import type { ThresholdConfig } from '../config/schema';
import type { Severity } from '../prompts/security-agent-prompts';
import { severityAtLeast } from '../severity';
import type { LocalFinding } from './local/types';

export interface ThresholdDecision {
  /** Findings at or above `blockOn`. A non-empty list means the commit is blocked. */
  blocking: LocalFinding[];
  /** Findings at or above `warnOn` but below `blockOn`: reported, allowed through. */
  warned: LocalFinding[];
  /** Count of findings per severity, for the summary line. */
  counts: Record<Severity, number>;
  /** Worst severity present, or null when there are no findings. */
  highest: Severity | null;
}

/**
 * Classifies findings against the configured thresholds.
 *
 * Blocking is tested first, so a finding can never appear in both lists. That
 * also makes a `warnOn` above `blockOn` harmless: everything at `warnOn` has
 * already been claimed by `blockOn`, so `warned` is simply empty and the
 * stricter setting wins.
 *
 * PRD §10.1 says the commit is blocked when the threshold is breached *and the
 * finding is unresolved*. In Local Mode nothing can be resolved — there is no
 * patch to apply (PRD §5.2) — so every breaching finding blocks. When the patch
 * flow arrives in Phase 5 it will filter resolved findings out before calling
 * this, which is why the input is a plain list rather than being read from disk.
 */
export function evaluateThreshold(
  findings: readonly LocalFinding[],
  threshold: ThresholdConfig,
): ThresholdDecision {
  const blocking: LocalFinding[] = [];
  const warned: LocalFinding[] = [];
  const counts: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  let highest: Severity | null = null;

  for (const finding of findings) {
    counts[finding.severity] += 1;

    if (severityAtLeast(finding.severity, threshold.blockOn)) {
      blocking.push(finding);
    } else if (severityAtLeast(finding.severity, threshold.warnOn)) {
      warned.push(finding);
    }

    if (highest === null || severityAtLeast(finding.severity, highest)) {
      highest = finding.severity;
    }
  }

  return { blocking, warned, counts, highest };
}
