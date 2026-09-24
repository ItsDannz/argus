/**
 * Severity ordering, defined once.
 *
 * Three separate places need to answer "is this at least as bad as that?":
 * config validation (is `warnOn` below `blockOn`?), threshold evaluation (does
 * this finding block the commit?), and the findings table (print worst first).
 * Duplicating the order in each of them is how you end up with a gate that
 * blocks on High in one code path and Medium in another.
 *
 * The ranks are spaced by 1 so an extra tier can be slotted in later without
 * renumbering.
 */

import type { Severity } from './prompts/security-agent-prompts';

/** All severities, worst first. Iteration order for summaries. */
export const SEVERITIES: readonly Severity[] = ['Critical', 'High', 'Medium', 'Low'];

export const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

/** True when `severity` is at or above `floor`. */
export function severityAtLeast(severity: Severity, floor: Severity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[floor];
}

/**
 * Narrowing guard for untrusted input (a hand-edited config file).
 *
 * Uses Object.hasOwn rather than `in` so a value like "constructor" or
 * "toString" does not pass by inheriting from Object.prototype.
 */
export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && Object.hasOwn(SEVERITY_RANK, value);
}
