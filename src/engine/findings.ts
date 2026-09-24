/**
 * The finding shape both engines produce.
 *
 * Local Mode and Remote Mode arrive at this from opposite directions — one from
 * a regex match on a single line, one from a model's JSON answer about a range
 * of lines — but everything downstream (the threshold, the terminal report, and
 * in Phase 5 the patch flow) only ever needs these five fields. Naming the
 * contract here is what lets the renderer and `evaluateThreshold` serve both
 * engines without a branch anywhere.
 *
 * Deliberately flat, and deliberately missing `suggested_patch`: a patch is not
 * a property of a finding, it is a follow-up proposal attached to one (see
 * `PatchSuggestion` in the prompts module). Keeping it out means a Local
 * finding cannot pretend to carry a fix it does not have — PRD §5.2 puts
 * auto-patching out of scope for Local Mode.
 */

import type { Severity } from '../prompts/security-agent-prompts';

export interface Finding {
  /** Path as it appears in the diff (no leading "a/" or "b/"). */
  file: string;
  /** 1-based line number in the new version of the file. */
  line: number;
  /**
   * Local Mode: the rule id, e.g. "hardcoded-secret". Remote Mode: the
   * vulnerability category from the model, e.g. "sql_injection". Both are short
   * stable identifiers that name the *kind* of problem, which is all any display
   * or grouping needs — so one field serves both rather than two that are never
   * both populated.
   */
  ruleId: string;
  severity: Severity;
  /** Human-readable explanation. Canned in Local Mode, model-written remotely. */
  message: string;
}
