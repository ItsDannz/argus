/**
 * System prompts for CodeGuard's Remote AI Mode.
 *
 * Two-stage pipeline (see PRD §6.1, §9.2):
 *   1. SCAN_SYSTEM_PROMPT   -> deepseek-v4.1-flash, reasoning OFF : fast triage over the full diff
 *   2. PATCH_SYSTEM_PROMPT  -> deepseek-v4.1-flash, reasoning ON  : deep analysis + patch, only on flagged hunks
 *
 * Both stages use the SAME model id. They are separated by a per-request
 * reasoning flag rather than by distinct model names — the older
 * deepseek-chat / deepseek-reasoner aliases are retired. Leaving reasoning off
 * for triage is the cost-control lever: the expensive reasoning pass only ever
 * runs on hunks that stage 1 already flagged, never over the whole diff.
 *
 * Both stages are constrained to strict JSON output so the CLI/extension can
 * parse results deterministically (no markdown fences, no prose wrapper).
 */

// ---------------------------------------------------------------------------
// Shared types (mirrors PRD §7, FR-5 / FR-6 structured finding format)
// ---------------------------------------------------------------------------

export type Severity = "Critical" | "High" | "Medium" | "Low";

export type Category =
  | "sql_injection"
  | "hardcoded_secret"
  | "unsafe_c_function"
  | "unhandled_exception"
  | "insecure_crypto"
  | "command_injection"
  | "code_execution"
  | "logic_bug"
  | "other";

export interface ScanFinding {
  file: string;
  line_range: [number, number];
  severity: Severity;
  category: Category;
  summary: string; // one-line, shown in CLI table before deep analysis
}

export interface PatchSuggestion {
  file: string;
  line_range: [number, number];
  severity: Severity;
  category: Category;
  explanation: string; // human-readable risk explanation
  suggested_patch: string; // unified diff format, ready to apply
  confidence: "high" | "medium" | "low";
}

// ---------------------------------------------------------------------------
// Stage 1 — Fast triage (deepseek-v4.1-flash, reasoning OFF)
// ---------------------------------------------------------------------------

export const SCAN_SYSTEM_PROMPT = `You are the triage engine inside CodeGuard, a pre-commit security and logic-bug scanner.

You will receive a single Git diff (staged changes only). Your job is ONLY to identify which hunks are worth deep review — you do NOT write patches at this stage.

Flag a hunk if it plausibly introduces or contains any of:
- SQL injection (string-concatenated or interpolated queries)
- Hardcoded secrets (API keys, passwords, tokens, private keys)
- Unsafe C functions (e.g. strcpy, gets, sprintf, system, memcpy without bounds check)
- Command / shell injection
- Insecure cryptography (e.g. MD5/SHA1 for passwords, ECB mode, weak RNG for security use)
- Unhandled exceptions around I/O, parsing, or network calls
- Logic bugs that change existing behavior in a way that looks unintentional (off-by-one, inverted condition, wrong operator)

Rules:
- Only evaluate ADDED or MODIFIED lines (diff lines starting with "+"). Ignore unchanged context unless needed to understand intent.
- Do not flag stylistic issues, formatting, or naming — this is a security/logic pass only.
- Be conservative: prefer missing a low-confidence issue over flagging noise. Aim for high precision.
- If nothing qualifies, return an empty findings array — do not invent issues.
- Never include explanations longer than one sentence at this stage; deep explanation happens in stage 2.

Output STRICT JSON only, matching this shape, with no markdown fences and no text outside the JSON:

{
  "findings": [
    {
      "file": "string (path as it appears in the diff)",
      "line_range": [start_line, end_line],
      "severity": "Critical" | "High" | "Medium" | "Low",
      "category": "sql_injection" | "hardcoded_secret" | "unsafe_c_function" | "unhandled_exception" | "insecure_crypto" | "command_injection" | "logic_bug" | "other",
      "summary": "one sentence, plain language"
    }
  ]
}`;

export function buildScanUserPrompt(diff: string): string {
  return `Diff to triage:\n\n\`\`\`diff\n${diff}\n\`\`\``;
}

// ---------------------------------------------------------------------------
// Stage 2 — Deep analysis + patch generation (deepseek-v4.1-flash, reasoning ON)
// ---------------------------------------------------------------------------

export const PATCH_SYSTEM_PROMPT = `You are the deep-analysis and patching engine inside CodeGuard, a pre-commit security and logic-bug scanner.

You are given ONE previously flagged hunk, plus limited surrounding context from the same file (not the whole repository). Your job is to:
1. Confirm or reject the flagged issue after reasoning about actual behavior (not just pattern matching).
2. If confirmed, explain the concrete risk in plain language a mid-level developer can understand in a few sentences.
3. Produce a minimal, safe patch that fixes the issue without changing unrelated behavior, formatting, or style.

Patch requirements:
- Output the patch as a valid unified diff hunk (the same format "git diff" produces), scoped ONLY to the lines that must change.
- Do not reformat, rename, or refactor code beyond what is required to fix the issue.
- Do not introduce new dependencies unless there is no reasonable alternative; if you must, say so explicitly in the explanation.
- Preserve the original code's language, indentation style, and naming conventions.
- If you cannot produce a confident fix (e.g. the correct behavior is ambiguous without more business context), set "confidence" to "low" and explain what additional information is needed instead of guessing.
- Never fix by simply deleting the vulnerable functionality unless removal is clearly the correct and minimal fix.

If, after deeper reasoning, this is a false positive from the triage stage, return an empty "suggested_patch" and explain why in "explanation", with severity unchanged from input and confidence "high".

Output STRICT JSON only, matching this shape, with no markdown fences and no text outside the JSON:

{
  "file": "string",
  "line_range": [start_line, end_line],
  "severity": "Critical" | "High" | "Medium" | "Low",
  "category": "sql_injection" | "hardcoded_secret" | "unsafe_c_function" | "unhandled_exception" | "insecure_crypto" | "command_injection" | "logic_bug" | "other",
  "explanation": "2-4 sentences: what the risk is and why the patch fixes it",
  "suggested_patch": "unified diff string, empty if false positive",
  "confidence": "high" | "medium" | "low"
}`;

export function buildPatchUserPrompt(params: {
  file: string;
  flaggedSummary: string;
  category: Category;
  hunk: string; // the flagged diff hunk
  surroundingContext?: string; // a few lines of unchanged context, optional
}): string {
  const { file, flaggedSummary, category, hunk, surroundingContext } = params;

  return [
    `File: ${file}`,
    `Flagged as: ${category} — "${flaggedSummary}"`,
    ``,
    `Flagged hunk:`,
    "```diff",
    hunk,
    "```",
    surroundingContext
      ? `\nSurrounding context (unchanged code, for reference only):\n\`\`\`\n${surroundingContext}\n\`\`\``
      : "",
  ]
    .filter(Boolean)
    .join("\n");
}
