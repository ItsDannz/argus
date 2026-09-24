/**
 * Holds Remote Mode to a severity floor set by the local rule engine (FR-5).
 *
 * ─── The problem this exists to solve ────────────────────────────────────────
 * The two engines answer the same question differently and nothing used to
 * reconcile them. A diff the rule engine rates Critical — a string-concatenated
 * SQL query, say, which is unambiguous to a regex — came back from the model as
 * High. Same code, same bug, two different commit outcomes: Local Mode refused
 * the commit, Remote Mode warned and let it through.
 *
 * That is not a parsing bug and not a bad model answer. It is an architectural
 * gap, and the same one from the other direction: a probabilistic judgement was
 * allowed to produce a WEAKER guarantee than a deterministic one, for a
 * vulnerability class the deterministic engine already has a fixed, confident
 * answer for. For a tool whose promise is "guard, not linter", which engine
 * happens to be configured must not decide whether a known-bad commit is
 * stopped.
 *
 * ─── The rule ────────────────────────────────────────────────────────────────
 * The rule set runs as a baseline in BOTH modes. In Local Mode it is the answer;
 * in Remote Mode it is the floor. Reconciliation is per (file, category):
 *
 *   - Remote reported that category in that file — each such finding's severity
 *     is raised to at least the rule engine's severity there. Never lowered.
 *   - The rule engine flags a line Remote did not report — its finding is added
 *     at that line. (Per line, not per group: see the merging section below.)
 *   - Deep analysis dismissed it as a false positive — the dismissal is
 *     overruled, because a dismissal is the extreme form of the same downgrade.
 *
 * Remote Mode keeps everything worth paying for: it can raise a severity, and it
 * can report categories the rules cannot see at all (`logic_bug`,
 * `unhandled_exception`, and anything contextual). What it loses is the ability
 * to be QUIETER than the regex engine about a class the regex engine flags.
 *
 * ─── Why the match is (file, category) and not (file, line) ──────────────────
 * Line numbers are not comparable between the engines. The rule engine reads a
 * parsed diff and knows exactly which line it matched; the model reads the same
 * diff as text and reports a range it inferred. Requiring those to agree would
 * mean choosing a line tolerance, which is a guess about model accuracy wearing
 * the costume of a constant.
 *
 * The two ways of being wrong are not symmetrical, which settles the direction.
 * A missed match is a silent downgrade — the bug this module exists to fix. A
 * spurious match raises the severity of a finding in a file where the rule
 * engine already reports that exact category, which lands in the safe direction.
 * So the match is deliberately generous, and it still cannot reach outside a
 * category the rule engine flagged: the rules never emit `logic_bug`, `other`,
 * or `unhandled_exception`, so the categories only Remote Mode can find are
 * never floored.
 *
 * ─── Merging a rule match into what the AI already reported ──────────────────
 * The severity floor is per (file, category) — a rule match anywhere in a file
 * sets the floor for that class across it. The question of whether a rule match
 * is a SEPARATE finding is per line, and gets the opposite answer: a match on a
 * line the AI also reported is the same occurrence and is dropped, because the
 * AI's row carries the explanation and possibly a patch. A match on any other
 * line in that file is a second occurrence and is kept as its own row.
 *
 * That distinction came from watching the tool disagree with itself. With deep
 * analysis succeeding, the report showed one consolidated finding; with deep
 * analysis failing and the scan falling back to triage, the same diff produced
 * three individual rows. The output shape depended on whether Stage 2 happened to
 * succeed, which is not something a developer should be able to observe. Merging
 * per line makes the successful path match the fallback path's granularity
 * instead of losing information relative to it.
 *
 * Exact line equality, not an overlapping range, and deliberately so. Both
 * engines number lines in the new file, so equality means the same line — whereas
 * a range would additionally absorb a rule match a line or two away, and the
 * model's line numbers are demonstrably approximate: a live run reported line 19
 * for a query the file has on line 18. Absorbing that would hide a real instance
 * of the same bug, which is the exact failure this module exists to prevent.
 * Showing a near-duplicate row is the cheaper mistake.
 */

import type { Category, Severity } from '../prompts/security-agent-prompts';
import { SEVERITY_RANK } from '../severity';
import type { Finding } from './findings';

export interface ReconcileInput {
  /** Findings the AI pipeline would have counted on its own. */
  counted: readonly Finding[];
  /** Findings deep analysis cleared as false positives. */
  dismissed: readonly Finding[];
  /** The deterministic rule-engine result for the same diff. */
  baseline: readonly Finding[];
}

export interface ReconcileResult {
  /** The final counted set: Remote's findings, floored and completed. */
  counted: Finding[];
  /**
   * The baseline findings added because Remote Mode reported nothing on their
   * line. Same objects as the corresponding entries in `counted`, returned
   * separately so a caller can tell an added finding from a reported one — they
   * arrived with no deep analysis and no patch.
   */
  reinstated: Finding[];
  /** Dismissals that survived. Any overruled one is reported as a note instead. */
  dismissed: Finding[];
  /** One line per correction, for the caller to append to its operational notes. */
  notes: string[];
}

/** `file` + `category` as one map key. NUL cannot occur in either. */
function groupKey(finding: Finding): string {
  return `${finding.file}\u0000${finding.category}`;
}

function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

/**
 * Collapses a model-written sentence to one bounded line.
 *
 * The renderer prints each note as a single `  - …` line, so an embedded newline
 * would break the list and an unbounded explanation would run off the terminal.
 */
function brief(text: string, limit = 160): string {
  const collapsed = text.replace(/\s+/g, ' ').trim();
  return collapsed.length <= limit ? collapsed : `${collapsed.slice(0, limit - 1)}…`;
}

/**
 * Restores line order within each file block.
 *
 * `counted` arrives in the order the pipeline happened to produce it: findings
 * that matched no hunk first, then one group per analysed hunk, then anything
 * reinstated from the rule engine. Those orders disagree, and the renderer
 * prints a file's findings in array order — so one file could be listed at line
 * 900 and then line 2. Sorting within a file (never across files; the file order
 * is diff order and worth keeping) restores the reading the report promises.
 * The sort is stable, so findings on the same line keep the order they arrived
 * in.
 */
function sortWithinFiles(findings: readonly Finding[]): Finding[] {
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = byFile.get(finding.file);
    if (existing === undefined) byFile.set(finding.file, [finding]);
    else existing.push(finding);
  }

  const ordered: Finding[] = [];
  for (const group of byFile.values()) {
    for (const finding of group.sort((a, b) => a.line - b.line)) ordered.push(finding);
  }
  return ordered;
}

/** One (file, category) group's floor, plus how many baseline findings set it. */
interface Floor {
  file: string;
  category: Category;
  severity: Severity;
  count: number;
}

/**
 * Applies the floor.
 *
 * Pure, and separate from the pipeline that calls it, because this is policy
 * rather than plumbing: what Remote Mode is and is not allowed to do to a
 * finding is worth being able to read in one place and test without a diff, a
 * model, or a network.
 */
export function reconcileWithBaseline(input: ReconcileInput): ReconcileResult {
  const floors = new Map<string, Floor>();
  for (const finding of input.baseline) {
    const key = groupKey(finding);
    const floor = floors.get(key);
    if (floor === undefined) {
      floors.set(key, {
        file: finding.file,
        category: finding.category,
        severity: finding.severity,
        count: 1,
      });
      continue;
    }
    floor.count += 1;
    if (SEVERITY_RANK[finding.severity] > SEVERITY_RANK[floor.severity]) {
      floor.severity = finding.severity;
    }
  }

  // An empty baseline means no floors and no reinstatements, so every loop below
  // passes its input through untouched. Local Mode is unaffected by this module
  // for the same reason: it never has a separate baseline to reconcile against.
  const counted: Finding[] = [];
  const raised = new Map<string, number>();
  for (const finding of input.counted) {
    const key = groupKey(finding);
    const floor = floors.get(key);
    if (floor === undefined || SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[floor.severity]) {
      counted.push(finding);
      continue;
    }
    counted.push({ ...finding, severity: floor.severity });
    raised.set(key, (raised.get(key) ?? 0) + 1);
  }

  // Which lines the AI already reported, per group. A rule match on one of them
  // is the same occurrence and is dropped; a rule match elsewhere in the file is
  // a second occurrence the AI said nothing about, and is kept.
  const reportedLines = new Map<string, Set<number>>();
  for (const finding of counted) {
    const key = groupKey(finding);
    const lines = reportedLines.get(key);
    if (lines === undefined) reportedLines.set(key, new Set([finding.line]));
    else lines.add(finding.line);
  }

  const reinstatedFindings: Finding[] = [];
  const reinstated = new Map<string, number>();
  for (const finding of input.baseline) {
    const key = groupKey(finding);
    if (reportedLines.get(key)?.has(finding.line) === true) continue;
    counted.push(finding);
    reinstatedFindings.push(finding);
    reinstated.set(key, (reinstated.get(key) ?? 0) + 1);
  }

  const dismissed: Finding[] = [];
  const overrideNotes: string[] = [];
  for (const entry of input.dismissed) {
    const floor = floors.get(groupKey(entry));
    if (floor === undefined) {
      dismissed.push(entry);
      continue;
    }
    overrideNotes.push(
      `Deep analysis cleared ${entry.category} in ${entry.file} as a false positive, but the local rule ` +
        `engine reports it there, so the local ${plural(floor.count, 'finding')} ` +
        `${floor.count === 1 ? 'was' : 'were'} kept. Deep analysis said: ${brief(entry.message)}`,
    );
  }

  const raiseNotes: string[] = [];
  const reinstatementNotes: string[] = [];
  for (const [key, floor] of floors) {
    const upgraded = raised.get(key);
    if (upgraded !== undefined) {
      raiseNotes.push(
        `The AI engine rated ${plural(upgraded, 'finding')} in ${floor.file} below the local rule engine's ` +
          `severity for ${floor.category}, so ${upgraded === 1 ? 'it was' : 'they were'} raised to ` +
          `${floor.severity}. A rule match is deterministic, and Remote Mode is not allowed to produce a ` +
          'weaker result than Local Mode for the same class of problem.',
      );
    }

    const added = reinstated.get(key);
    if (added !== undefined) {
      // Two shapes of the same correction, because the difference is worth
      // reading: "the AI found none of this" and "the AI found some of this and
      // missed the rest" call for quite different amounts of developer trust.
      const headline = reportedLines.has(key)
        ? `The AI engine reported ${floor.category} in ${floor.file}, but the local rule engine flags ` +
          `${plural(added, 'other line')} there, so ` +
          `${added === 1 ? 'that finding was' : 'those findings were'} kept.`
        : `The AI scan reported no ${floor.category} in ${floor.file}, but the local rule engine did, so ` +
          `${plural(added, 'local finding')} ${added === 1 ? 'was' : 'were'} kept.`;
      reinstatementNotes.push(
        `${headline} Remote Mode is not allowed to produce a weaker result than Local Mode for the same ` +
          'class of problem.',
      );
    }
  }

  return {
    counted: sortWithinFiles(counted),
    reinstated: reinstatedFindings,
    dismissed,
    notes: [...raiseNotes, ...reinstatementNotes, ...overrideNotes],
  };
}
