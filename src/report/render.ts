/**
 * Human-readable report rendering (NFR Usability: severity + location + a
 * one-line explanation, never raw JSON dumped at the terminal).
 *
 * All rendering is pure string building — nothing here writes to a stream or
 * reads the environment. That keeps it directly assertable in tests, and leaves
 * the questions of *where* output goes and whether colour is appropriate to the
 * caller, which is the only place that can answer them (a TTY check, NO_COLOR).
 *
 * No dependency is used for this. Adding one for padding and a wrap would not
 * be justifiable against PRD §9.1's stack.
 */

import type { ConfigProblem } from '../config/schema';
import type { LocalFinding } from '../engine/local/types';
import type { ThresholdDecision } from '../engine/threshold';
import type { Severity } from '../prompts/security-agent-prompts';

/**
 * ANSI escapes, as literal-keyed constants so every use site is a plain string.
 * A `Record<string, string>` would type each lookup as possibly-undefined and
 * force a `!` at each of them.
 */
const ANSI = {
  reset: '\u001b[0m',
  bold: '\u001b[1m',
  dim: '\u001b[2m',
  red: '\u001b[31m',
  green: '\u001b[32m',
  yellow: '\u001b[33m',
} as const;

const SEVERITY_COLOUR: Record<Severity, string> = {
  Critical: ANSI.bold + ANSI.red,
  High: ANSI.red,
  Medium: ANSI.yellow,
  Low: ANSI.dim,
};

const SEVERITY_WIDTH = 8; // "Critical" is the longest severity name.
const MESSAGE_INDENT = '        ';
const WRAP_WIDTH = 76;

export interface RenderOptions {
  /** Wrap labels in ANSI colour. Caller must check TTY and NO_COLOR. */
  useColor?: boolean;
  /**
   * Which engine produced the findings, named in the report header.
   *
   * Worth stating because the two modes give different guarantees: Local Mode is
   * detection-only and can never have produced a patch, and Remote Mode may have
   * declined to analyse part of the diff. A reader who does not know which one
   * ran cannot know how much of the report to trust. Defaults to local.
   */
  engine?: EngineName;
}

export type EngineName = 'local' | 'remote';

const ENGINE_LABEL: Record<EngineName, string> = {
  local: 'local engine',
  remote: 'remote AI engine',
};

/** No-op when colour is off, so call sites never need to branch. */
function makePainter(options: RenderOptions): (text: string, colour: string) => string {
  if (options.useColor !== true) return (text) => text;
  return (text, colour) => `${colour}${text}${ANSI.reset}`;
}

/** `1 issue` / `2 issues`, without the "(s)" that reads like a template. */
function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

/**
 * Greedy word wrap, with every line indented.
 *
 * `width` bounds the finished line, indent included — not the content before
 * the indent is added. Measuring the content alone would let an indented line
 * run `indent.length` characters past the intended limit and wrap awkwardly in
 * an 80-column terminal.
 *
 * A word longer than the available space (a long identifier, a URL) is emitted
 * whole rather than split — breaking mid-identifier would make the message
 * harder to read, and the overflow is only cosmetic.
 */
function wrap(text: string, indent: string, width = WRAP_WIDTH): string {
  const available = Math.max(1, width - indent.length);
  const lines: string[] = [];
  let line = '';
  for (const word of text.split(/\s+/).filter((part) => part !== '')) {
    if (line === '') {
      line = word;
    } else if (line.length + 1 + word.length <= available) {
      line += ` ${word}`;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line !== '') lines.push(line);
  return lines.map((entry) => indent + entry).join('\n');
}

/** Findings grouped by file, preserving diff order within each file. */
function groupByFile(findings: readonly LocalFinding[]): Map<string, LocalFinding[]> {
  const grouped = new Map<string, LocalFinding[]>();
  for (const finding of findings) {
    const existing = grouped.get(finding.file);
    if (existing === undefined) grouped.set(finding.file, [finding]);
    else existing.push(finding);
  }
  return grouped;
}

/**
 * The findings table.
 *
 * Grouped by file rather than sorted by severity: a developer fixing these is
 * opening one file at a time, so file-first is the order the work happens in.
 * Severity is still the leftmost column of every row.
 */
export function renderFindings(findings: readonly LocalFinding[], options: RenderOptions = {}): string {
  if (findings.length === 0) return '';

  const paint = makePainter(options);
  const blocks: string[] = [];

  for (const [file, fileFindings] of groupByFile(findings)) {
    const rows = fileFindings.map((finding) => {
      // Padded before colouring: ANSI escapes have width, padEnd does not know that.
      const label = finding.severity.padEnd(SEVERITY_WIDTH);
      const location = `${String(finding.line).padStart(5)}  `;
      return [
        `    ${location}${paint(label, SEVERITY_COLOUR[finding.severity])}  ${finding.ruleId}`,
        wrap(finding.message, MESSAGE_INDENT),
      ].join('\n');
    });
    blocks.push(`  ${paint(file, ANSI.bold)}\n\n${rows.join('\n\n')}`);
  }

  return blocks.join('\n\n');
}

function summariseCounts(counts: Record<Severity, number>): string {
  return (['Critical', 'High', 'Medium', 'Low'] as const)
    .filter((severity) => counts[severity] > 0)
    .map((severity) => `${counts[severity]} ${severity}`)
    .join(', ');
}

/**
 * The header line plus the body.
 *
 * The engine is named in the output because the two modes give different
 * guarantees — Local Mode is detection-only and cannot have applied a patch —
 * and the reader needs to know which one produced what they are looking at.
 */
export function renderFindingsReport(
  findings: readonly LocalFinding[],
  options: RenderOptions = {},
): string {
  const paint = makePainter(options);
  const engine = ENGINE_LABEL[options.engine ?? 'local'];
  if (findings.length === 0) {
    return paint(`CodeGuard (${engine}): no issues found in the staged changes.`, ANSI.green);
  }

  const fileCount = groupByFile(findings).size;
  const header = `CodeGuard (${engine}): ${plural(findings.length, 'issue')} in ${plural(fileCount, 'file')}`;
  return `${header}\n\n${renderFindings(findings, options)}`;
}

/**
 * Operational notes from a remote scan — exclusions, redactions, truncation,
 * the hunk cap, a partial outage.
 *
 * Goes to stderr, for the same reason the config warning does: it is about how
 * the scan ran rather than about the code, and it must not pollute a report that
 * someone might be parsing. The `[CODEGUARD]` marker is plain text so it keeps
 * its shape with `--no-color`.
 *
 * Every note is phrased as a statement of what CodeGuard did NOT do, because
 * that is the only thing here a developer cannot infer from the findings list.
 * An empty result and a truncated result look identical otherwise.
 */
export function renderNotes(notes: readonly string[], options: RenderOptions = {}): string {
  if (notes.length === 0) return '';
  const paint = makePainter(options);
  return [
    paint('[CODEGUARD]', ANSI.yellow),
    ...notes.map((note) => `  - ${note}`),
  ].join('\n');
}

/**
 * The false positives a remote scan cleared, and the patches it proposed.
 *
 * Both are printed BELOW the findings and outside the verdict, because neither
 * one affects the commit decision: a cleared finding does not count towards the
 * threshold, and a patch that has not been applied fixes nothing. Printing
 * either one above the verdict would imply a weight it does not have.
 *
 * The `extra` argument is shape-compatible with the remote engine's result but
 * declared structurally, so this module keeps no runtime dependency on it.
 */
export function renderRemoteExtras(
  extra: {
    dismissed: readonly LocalFinding[];
    analyses: readonly {
      file: string;
      line: number;
      confidence: string;
      patch: string;
      withheld: string | null;
    }[];
  },
  options: RenderOptions = {},
): string {
  const paint = makePainter(options);
  const blocks: string[] = [];

  if (extra.dismissed.length > 0) {
    const rows = extra.dismissed.map((finding) =>
      [`    ${String(finding.line).padStart(5)}  ${finding.ruleId}`, wrap(finding.message, MESSAGE_INDENT)].join(
        '\n',
      ),
    );
    blocks.push(
      [
        paint(
          `Cleared as false positives by deep analysis (${plural(extra.dismissed.length, 'finding')}, not counted):`,
          ANSI.dim,
        ),
        '',
        rows.join('\n\n'),
      ].join('\n'),
    );
  }

  const patches = extra.analyses.filter((analysis) => analysis.patch !== '' || analysis.withheld !== null);
  if (patches.length > 0) {
    const rows = patches.map((analysis) => {
      const heading = `    ${analysis.file}:${analysis.line}  (confidence: ${analysis.confidence})`;
      if (analysis.patch === '') {
        // A patch exists but cannot be shown — the redaction fail-safe. Saying
        // why is the difference between "the model had no fix" and "there is a
        // fix you will have to write yourself".
        return `${heading}\n${wrap(analysis.withheld ?? '', MESSAGE_INDENT)}`;
      }
      return `${heading}\n${analysis.patch
        .split('\n')
        .map((line) => `${MESSAGE_INDENT}${line}`)
        .join('\n')}`;
    });
    blocks.push(
      [
        paint(
          `Suggested ${plural(patches.length, 'patch', 'patches')} — review and apply (nothing is changed yet):`,
          ANSI.bold,
        ),
        '',
        rows.join('\n\n'),
      ].join('\n'),
    );
  }

  return blocks.join('\n\n');
}

/**
 * The verdict: what the threshold means for this commit.
 *
 * This is the text a developer reads while their commit is being refused, so it
 * states the threshold that fired, what to do next, and the escape hatch — PRD
 * §10.1 asks for the override to be documented, and PRD §11 accepts that
 * `--no-verify` exists rather than trying to defeat it. Naming it here means
 * nobody has to reach for it in frustration before reading it.
 */
export function renderVerdict(
  decision: ThresholdDecision,
  blockOn: Severity,
  warnOn: Severity,
  options: RenderOptions = {},
): string {
  const paint = makePainter(options);

  if (decision.blocking.length > 0) {
    return [
      paint(
        `Commit blocked: ${plural(decision.blocking.length, 'issue')} at or above the block threshold "${blockOn}".`,
        ANSI.red,
      ),
      `  Found: ${summariseCounts(decision.counts)}.`,
      '',
      'Fix the issues above, then stage the fixes and commit again.',
      'To commit anyway:  git commit --no-verify',
    ].join('\n');
  }

  if (decision.warned.length > 0) {
    return [
      paint(
        `Commit allowed, with ${plural(decision.warned.length, 'warning')} at or above "${warnOn}" (blocking starts at "${blockOn}").`,
        ANSI.yellow,
      ),
      `  Found: ${summariseCounts(decision.counts)}.`,
    ].join('\n');
  }

  return 'No issues at or above the configured threshold.';
}

/**
 * A warning block for config problems.
 *
 * Goes to stderr, and is deliberately verbose: this is printed on every single
 * commit until the file is fixed, which is what stops a broken config from
 * quietly becoming a config nobody notices is being ignored.
 *
 * The `[CONFIG ERROR]` marker is PLAIN TEXT, not colour, on purpose. Colour is
 * off whenever stdout is not a terminal — which is exactly the case inside a
 * pre-commit hook — so a warning signalled only by colour would arrive at the
 * developer as ordinary prose. The marker has to survive `--no-color`.
 *
 * The trailing lines state the policy and name the fix. A developer whose
 * commit just succeeded over a broken config needs to know two things: that the
 * settings were ignored (so a stricter-than-default threshold did not apply),
 * and how to check the file without waiting for the next commit.
 */
export function renderConfigProblems(
  problems: readonly ConfigProblem[],
  configPath: string | null,
  options: RenderOptions = {},
): string {
  if (problems.length === 0) return '';

  const paint = makePainter(options);
  const lines = problems.map((problem) =>
    problem.where === '' ? `  - ${problem.message}` : `  - ${problem.where}: ${problem.message}`,
  );
  const where = configPath ?? 'the configuration';
  const headline = `CodeGuard found ${plural(problems.length, 'problem')} in ${where}`;

  return [
    `${paint('[CONFIG ERROR]', ANSI.yellow)} ${paint(headline, ANSI.bold)}`,
    ...lines,
    '  These settings were ignored — CodeGuard continued with its defaults.',
    '  Check this file with:  codeguard config --validate',
  ].join('\n');
}
