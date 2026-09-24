/**
 * Parsing and validating model output.
 *
 * Everything here treats the model's answer as UNTRUSTED INPUT. It is text from
 * a third party that we are about to turn into findings that can block a
 * developer's commit and, in Phase 5, patches that get written to their files.
 * "The prompt asked for strict JSON, so it will be strict JSON" is not a
 * guarantee, and a `.severity` that turns out to be `undefined` propagates into
 * a threshold comparison that quietly never fires.
 *
 * So the shape is checked field by field, and anything that fails is reported
 * rather than guessed at. The two exceptions are deliberate and asymmetric —
 * see `normaliseFinding`.
 */

import type {
  Category,
  PatchSuggestion,
  ScanFinding,
  Severity,
} from '../../prompts/security-agent-prompts';
import { isSeverity } from '../../severity';

/**
 * Every category the model is allowed to use.
 *
 * A `Record` keyed by the union, so adding a member to `Category` without
 * listing it here is a compile error rather than a category that silently
 * becomes "other". Same trick as the prompt-enum guard in
 * prompts/__tests__/prompts.test.ts, and it exists for the same reason: the
 * type union alone does not reach the model.
 */
const KNOWN_CATEGORIES: Record<Category, true> = {
  sql_injection: true,
  hardcoded_secret: true,
  unsafe_c_function: true,
  unhandled_exception: true,
  insecure_crypto: true,
  command_injection: true,
  code_execution: true,
  logic_bug: true,
  other: true,
};

function isCategory(value: unknown): value is Category {
  return typeof value === 'string' && Object.hasOwn(KNOWN_CATEGORIES, value);
}

const CONFIDENCES = ['high', 'medium', 'low'] as const;
type Confidence = (typeof CONFIDENCES)[number];

function isConfidence(value: unknown): value is Confidence {
  return typeof value === 'string' && (CONFIDENCES as readonly string[]).includes(value);
}

/**
 * A ceiling on findings from one response.
 *
 * Not a product limit — a runaway guard. A model that enters a loop and emits
 * thousands of findings would otherwise be turned into thousands of API calls
 * by Stage 2 and a terminal report nobody can read.
 */
const MAX_FINDINGS = 200;

/** Longest explanation we will carry into the report before truncating. */
const MAX_TEXT = 2000;

export interface ParseOutcome<T> {
  value: T;
  /** Entries that were refused, each with a plain-language reason. */
  rejected: string[];
}

/**
 * Removes a markdown code fence if the model wrapped its JSON in one.
 *
 * Both prompts say not to. Models do it anyway, and the alternative to
 * tolerating it is a failed scan for a cosmetic reason.
 */
function stripFences(text: string): string {
  const trimmed = text.trim();
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/.exec(trimmed);
  return fenced?.[1] ?? trimmed;
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(stripFences(text));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`the model's response was not valid JSON — ${message}`);
  }
}

/** Strips the `a/` or `b/` prefix, so a literal echo of the diff header matches. */
function normalisePath(value: string): string {
  return value.trim().replace(/^[ab]\//, '');
}

function isLineRange(value: unknown): value is [number, number] {
  return (
    Array.isArray(value) &&
    value.length === 2 &&
    value.every((entry) => typeof entry === 'number' && Number.isInteger(entry) && entry >= 1) &&
    (value[0] as number) <= (value[1] as number)
  );
}

function asText(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed === '') return null;
  return trimmed.length > MAX_TEXT ? `${trimmed.slice(0, MAX_TEXT)}…` : trimmed;
}

export interface TriageOptions {
  /**
   * Paths that appeared in the diff we sent. A finding naming anything else is
   * discarded: there is no hunk to attach it to, and a hallucinated path would
   * otherwise become a finding the developer cannot act on.
   */
  knownFiles: ReadonlySet<string>;
}

/**
 * Validates one triage finding.
 *
 * The asymmetric part: an unusable `category` is coerced to `other`, while an
 * unusable `severity` rejects the whole finding.
 *
 * Category is a label. Getting it wrong costs a slightly misleading group
 * heading, and discarding a real vulnerability over a taxonomy typo would be
 * the worse outcome.
 *
 * Severity is a decision input — it is what the threshold compares against. A
 * guessed default either blocks a commit that should have passed or waves
 * through one that should not, and both are worse than admitting the one entry
 * could not be used. The caller reports every rejection, so this is never a
 * silent loss.
 */
function normaliseFinding(raw: unknown, knownFiles: ReadonlySet<string>): ScanFinding | string {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return 'entry was not an object';
  }
  const record = raw as Record<string, unknown>;

  const file = typeof record['file'] === 'string' ? normalisePath(record['file']) : '';
  if (file === '') return 'entry had no file path';
  if (!knownFiles.has(file)) return `entry named "${file}", which was not in the diff`;

  if (!isLineRange(record['line_range'])) {
    return `entry for ${file} had no usable line_range`;
  }
  if (!isSeverity(record['severity'])) {
    return `entry for ${file} had unusable severity ${JSON.stringify(record['severity'])}`;
  }

  const summary = asText(record['summary']);
  if (summary === null) return `entry for ${file} had no summary`;

  const category: Category = isCategory(record['category']) ? record['category'] : 'other';

  return {
    file,
    line_range: record['line_range'],
    severity: record['severity'],
    category,
    summary,
  };
}

/**
 * Parses a Stage-1 (triage) response.
 *
 * @throws when the response is not JSON at all — the caller treats that as a
 *         provider failure and degrades to Local Mode.
 */
export function parseTriageResponse(text: string, options: TriageOptions): ParseOutcome<ScanFinding[]> {
  const parsed = parseJson(text);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('the model\'s response was not a JSON object');
  }

  const raw = (parsed as Record<string, unknown>)['findings'];
  if (raw === undefined || raw === null) return { value: [], rejected: [] };
  if (!Array.isArray(raw)) throw new Error('the model\'s "findings" field was not an array');

  const rejected: string[] = [];
  if (raw.length > MAX_FINDINGS) {
    rejected.push(`the model returned ${raw.length} findings; only the first ${MAX_FINDINGS} were considered`);
  }

  const findings: ScanFinding[] = [];
  for (const entry of raw.slice(0, MAX_FINDINGS)) {
    const result = normaliseFinding(entry, options.knownFiles);
    if (typeof result === 'string') rejected.push(result);
    else findings.push(result);
  }

  return { value: findings, rejected };
}

/**
 * Parses a Stage-2 (deep analysis) response.
 *
 * An empty `suggested_patch` is the documented way for the model to say "this
 * was a false positive" (see PATCH_SYSTEM_PROMPT), so it is a valid outcome and
 * not a parse failure.
 *
 * `confidence` falls back to `low` rather than rejecting, because the field is
 * advisory: it is shown to the developer next to a patch they must approve by
 * hand. Guessing low is the direction that makes them look harder.
 *
 * @throws when the response is not JSON at all.
 */
export function parsePatchResponse(
  text: string,
  knownFiles: ReadonlySet<string>,
): ParseOutcome<PatchSuggestion | null> {
  const parsed = parseJson(text);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('the model\'s response was not a JSON object');
  }
  const record = parsed as Record<string, unknown>;

  const file = typeof record['file'] === 'string' ? normalisePath(record['file']) : '';
  if (file === '' || !knownFiles.has(file)) {
    return { value: null, rejected: [`deep-analysis result named "${file}", which was not in the diff`] };
  }
  if (!isSeverity(record['severity'])) {
    return {
      value: null,
      rejected: [`deep-analysis result for ${file} had unusable severity ${JSON.stringify(record['severity'])}`],
    };
  }

  const explanation = asText(record['explanation']);
  if (explanation === null) {
    return { value: null, rejected: [`deep-analysis result for ${file} had no explanation`] };
  }

  // Absent, empty and whitespace-only all mean "no patch" — the false-positive
  // signal. Anything non-string is a malformed answer to a field we act on, so
  // the result is refused rather than coerced to empty, which would read as a
  // confident "not a problem".
  const patch = record['suggested_patch'];
  if (patch !== undefined && patch !== null && typeof patch !== 'string') {
    return {
      value: null,
      rejected: [`deep-analysis result for ${file} had a non-string suggested_patch`],
    };
  }

  return {
    value: {
      file,
      line_range: isLineRange(record['line_range']) ? record['line_range'] : [1, 1],
      severity: record['severity'],
      category: isCategory(record['category']) ? record['category'] : 'other',
      explanation,
      suggested_patch: typeof patch === 'string' ? patch.trim() : '',
      confidence: isConfidence(record['confidence']) ? record['confidence'] : 'low',
    },
    rejected: [],
  };
}

export type { Category, PatchSuggestion, ScanFinding, Severity };
