/**
 * Types for the Local Static Engine (PRD §6.2, FR-8).
 *
 * The Local Engine is detection-only: it can say "this line looks like a raw SQL
 * query" but never proposes a fix. That is why `LocalFinding` deliberately has no
 * `suggested_patch` field — auto-patching is a Remote Mode capability only.
 */

import type { Severity } from '../../prompts/security-agent-prompts';

/**
 * A single rule match against a diff hunk.
 *
 * Note this is a *flatter* shape than `ScanFinding` from the prompts module:
 * a rule either matches a line or it doesn't, so there is no `line_range` and no
 * prose `summary` — just the offending line and the rule's canned message.
 */
export interface LocalFinding {
  /** Path as it appears in the diff (no leading "a/" or "b/"). */
  file: string;
  /** 1-based line number in the new version of the file. */
  line: number;
  /** Stable rule identifier, e.g. "hardcoded-secret". Used for config overrides. */
  ruleId: string;
  severity: Severity;
  /** Canned, human-readable explanation of why this pattern is dangerous. */
  message: string;
}
