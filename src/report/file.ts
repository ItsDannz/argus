/**
 * The local scan report (FR-12).
 *
 * A machine-readable copy of the last scan, written to `.codeguard/report.json`
 * so findings outlive the terminal they were printed in — for a later look, for
 * `codeguard patch --from-report`, and for whatever a developer wants to do with
 * the JSON themselves.
 *
 * ─── Failure policy ──────────────────────────────────────────────────────────
 * Writing never fails a scan. A report is a convenience; a pre-commit gate that
 * blocks a commit because it could not write a cache file would be trading the
 * thing it is for against a thing it is not. So a write error is returned as a
 * note and the scan carries on — the same fail-open-on-operational-errors axis
 * as the rest of the hook.
 *
 * ─── The one privacy note ────────────────────────────────────────────────────
 * The report holds `suggested_patch` text, which is a copy of the developer's
 * own source, and it holds no credential: the diff was redacted before it was
 * sent, and the key never reaches a finding. It lands in `.codeguard/`, and
 * `codeguard install` adds that entry to `.gitignore` in repositories that do
 * not already have one (PRD §11 ships the ignore by default), because a file
 * that can contain source should not be one `git add -A` away from history.
 * See `ensureReportIgnored` below for what that write does and does not do.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { Finding } from '../engine/findings';
import type { DeepAnalysis } from '../engine/remote';
import type { EngineName } from './render';

export const REPORT_DIRECTORY = '.codeguard';
export const REPORT_FILENAME = 'report.json';

/**
 * Bumped when the shape changes incompatibly.
 *
 * Read back rather than ignored: a report from an older CodeGuard is a file
 * full of plausible-looking fields that no longer mean what the reader thinks,
 * and refusing it by version is cheaper than validating every field.
 */
export const REPORT_VERSION = 1;

export interface ReportFile {
  version: number;
  /** ISO 8601, so a stale report can be recognised as stale. */
  generatedAt: string;
  engine: EngineName;
  findings: Finding[];
  dismissed: Finding[];
  analyses: DeepAnalysis[];
  notes: string[];
}

/** Absolute path of the report for a repository. */
export function reportPath(repoRoot: string): string {
  return path.join(repoRoot, REPORT_DIRECTORY, REPORT_FILENAME);
}

export interface ReportInput {
  engine: EngineName;
  findings: readonly Finding[];
  dismissed: readonly Finding[];
  analyses: readonly DeepAnalysis[];
  notes: readonly string[];
}

/** Serialises the scan into a `ReportFile`. Pure, so the shape is testable. */
export function buildReport(input: ReportInput, now: Date = new Date()): ReportFile {
  return {
    version: REPORT_VERSION,
    generatedAt: now.toISOString(),
    engine: input.engine,
    findings: [...input.findings],
    dismissed: [...input.dismissed],
    analyses: [...input.analyses],
    notes: [...input.notes],
  };
}

export interface WriteReportResult {
  /** Repo-relative path written, or null when the write did not happen. */
  path: string | null;
  /** Why it did not happen. Null on success. */
  problem: string | null;
}

/**
 * Writes the report, reporting rather than throwing on failure.
 *
 * The directory is created if it is missing: `.codeguard/` is ignored by Git,
 * so it will not exist in a fresh clone, and a report that only appears on the
 * second scan would be a strange thing to explain.
 */
export async function writeReport(repoRoot: string, input: ReportInput): Promise<WriteReportResult> {
  const target = reportPath(repoRoot);
  try {
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, `${JSON.stringify(buildReport(input), null, 2)}\n`, 'utf8');
    return { path: `${REPORT_DIRECTORY}/${REPORT_FILENAME}`, problem: null };
  } catch (error) {
    return {
      path: null,
      problem: `could not write ${REPORT_DIRECTORY}/${REPORT_FILENAME} — ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }
}

export type ReadReportResult =
  | { ok: true; report: ReportFile; path: string }
  | { ok: false; reason: string };

/** The entry that keeps the report out of history. */
export const IGNORE_ENTRY = `${REPORT_DIRECTORY}/`;

/**
 * Whether an existing `.gitignore` already covers the report directory.
 *
 * Matched as whole lines rather than by substring, because `dist/.codeguard/`
 * is a different rule and `.codeguardrc.json` — a file this project expects to
 * be committed — contains the same characters.
 */
function alreadyIgnored(contents: string): boolean {
  const wanted = new Set([IGNORE_ENTRY, REPORT_DIRECTORY, `/${IGNORE_ENTRY}`, `/${REPORT_DIRECTORY}`]);
  return contents
    .split(/\r?\n/)
    .map((line) => line.trim())
    .some((line) => wanted.has(line));
}

export interface IgnoreResult {
  /** True when this call wrote the entry. */
  changed: boolean;
  /** Why it could not, when it could not. */
  problem: string | null;
}

/**
 * Adds `.codeguard/` to the repository's `.gitignore` if it is not there.
 *
 * Called by `codeguard install`, and it is a WRITE to a file the developer
 * owns, so it is additive and one line: it never rewrites the file, never
 * reorders it, and it is reported when it happens. The entry matters because
 * the report contains `suggested_patch` — copies of the developer's own source.
 * A file like that should not be one `git add -A` away from history, and PRD §11
 * expects CodeGuard to ship the ignore by default.
 *
 * A failure here is reported, never thrown: an install that succeeded in every
 * other respect should not be undone by an unreadable `.gitignore`.
 */
export async function ensureReportIgnored(repoRoot: string): Promise<IgnoreResult> {
  const target = path.join(repoRoot, '.gitignore');

  let contents = '';
  try {
    contents = await readFile(target, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      return { changed: false, problem: `could not read .gitignore — ${message(error)}` };
    }
  }

  if (alreadyIgnored(contents)) return { changed: false, problem: null };

  try {
    const separator = contents === '' || contents.endsWith('\n') ? '' : '\n';
    await writeFile(target, `${contents}${separator}${IGNORE_ENTRY}\n`, 'utf8');
    return { changed: true, problem: null };
  } catch (error) {
    return { changed: false, problem: `could not write .gitignore — ${message(error)}` };
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Reads the report back, refusing anything it cannot vouch for.
 *
 * Validated rather than cast. `--from-report` decides what gets written to the
 * developer's files based on this data, so a truncated or hand-edited file has
 * to be rejected with a reason instead of producing findings with undefined
 * fields.
 */
export async function readReport(repoRoot: string): Promise<ReadReportResult> {
  const target = reportPath(repoRoot);
  const shown = `${REPORT_DIRECTORY}/${REPORT_FILENAME}`;

  let text: string;
  try {
    text = await readFile(target, 'utf8');
  } catch (error) {
    return {
      ok: false,
      reason:
        (error as NodeJS.ErrnoException).code === 'ENOENT'
          ? `there is no ${shown} yet — run \`codeguard scan\` first`
          : `could not read ${shown} — ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return { ok: false, reason: `${shown} is not valid JSON — ${error instanceof Error ? error.message : String(error)}` };
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return { ok: false, reason: `${shown} does not contain a report object` };
  }
  const candidate = parsed as Partial<ReportFile>;
  if (candidate.version !== REPORT_VERSION) {
    return {
      ok: false,
      reason:
        `${shown} was written by a different version of CodeGuard (report version ` +
        `${String(candidate.version)}, this build reads ${REPORT_VERSION}) — run \`codeguard scan\` again`,
    };
  }
  if (!Array.isArray(candidate.findings) || !Array.isArray(candidate.analyses)) {
    return { ok: false, reason: `${shown} is missing its findings or analyses` };
  }

  return {
    ok: true,
    path: shown,
    report: {
      version: REPORT_VERSION,
      generatedAt: typeof candidate.generatedAt === 'string' ? candidate.generatedAt : '',
      engine: candidate.engine === 'remote' ? 'remote' : 'local',
      findings: candidate.findings,
      dismissed: Array.isArray(candidate.dismissed) ? candidate.dismissed : [],
      analyses: candidate.analyses,
      notes: Array.isArray(candidate.notes) ? candidate.notes : [],
    },
  };
}
