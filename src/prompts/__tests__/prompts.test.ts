import { describe, expect, it } from '@jest/globals';

import {
  PATCH_SYSTEM_PROMPT,
  SCAN_SYSTEM_PROMPT,
  buildPatchUserPrompt,
  buildScanUserPrompt,
  type Category,
} from '../security-agent-prompts';

/**
 * Exhaustiveness guard over the Category union.
 *
 * TypeScript cannot enumerate a union at runtime, but a Record keyed by one must
 * name every member — so adding a category to the union without adding it here
 * is a compile error, and `npm test` runs `tsc` before Jest.
 *
 * This exists because the union and the prompts drifted once already. A new
 * category was added to the type and was silently inert in Remote Mode: the
 * model learns which categories exist only from the literal enum written into
 * the system prompt, never from the TypeScript type. A type-only change looks
 * like it worked and does nothing.
 */
const ALL_CATEGORIES: Record<Category, true> = {
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

/** Pulls the quoted category names out of a prompt's JSON output schema. */
function categoryEnumIn(prompt: string): string[] {
  const declaration = /"category":\s*((?:"[a-z_]+"\s*(?:\|\s*)?)+)/.exec(prompt);
  if (!declaration?.[1]) return [];
  return [...declaration[1].matchAll(/"([a-z_]+)"/g)].map((match) => match[1]!);
}

describe('prompt / Category union consistency', () => {
  const declared = Object.keys(ALL_CATEGORIES).sort();

  it.each([
    ['SCAN_SYSTEM_PROMPT', SCAN_SYSTEM_PROMPT],
    ['PATCH_SYSTEM_PROMPT', PATCH_SYSTEM_PROMPT],
  ])('%s advertises exactly the categories the union declares', (_name, prompt) => {
    expect(categoryEnumIn(prompt).sort()).toEqual(declared);
  });

  it('finds an enum to compare against at all', () => {
    // Without this, a prompt reworded so the regex no longer matches would make
    // categoryEnumIn return [] — which the test above would report as a
    // mismatch, but this pins the failure to its actual cause.
    expect(categoryEnumIn(SCAN_SYSTEM_PROMPT)).toHaveLength(declared.length);
  });

  it('lists dynamic code execution as a risk to flag, not just as an enum value', () => {
    // Fixing only the enum would leave stage 1 triage never flagging these
    // hunks, so a hunk would never reach stage 2 and the category would still
    // never surface in a real report. The bullet and the enum are both needed.
    expect(SCAN_SYSTEM_PROMPT).toMatch(/\beval\b/);
    expect(SCAN_SYSTEM_PROMPT).toMatch(/Function constructor/);
  });
});

describe('buildScanUserPrompt / buildPatchUserPrompt', () => {
  it('wraps the diff in a fenced block', () => {
    expect(buildScanUserPrompt('+eval(x)')).toBe('Diff to triage:\n\n```diff\n+eval(x)\n```');
  });

  it('omits the context block when no surrounding context is given', () => {
    const prompt = buildPatchUserPrompt({
      file: 'a.js',
      flaggedSummary: 'eval on user input',
      category: 'code_execution',
      hunk: '+eval(x)',
    });
    expect(prompt).toContain('File: a.js');
    expect(prompt).toContain('Flagged as: code_execution');
    expect(prompt).not.toContain('Surrounding context');
  });

  it('includes the context block when context is given', () => {
    const prompt = buildPatchUserPrompt({
      file: 'a.js',
      flaggedSummary: 'eval on user input',
      category: 'code_execution',
      hunk: '+eval(x)',
      surroundingContext: 'const x = 1;',
    });
    expect(prompt).toContain('Surrounding context');
    expect(prompt).toContain('const x = 1;');
  });
});
