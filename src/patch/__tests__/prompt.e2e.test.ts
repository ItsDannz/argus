/**
 * The interactive binding, loaded the way the CLI loads it.
 *
 * `prompt.ts` is the one module in the patch flow that cannot be imported by a
 * Jest test: inquirer 14 is a pure-ESM package, and Jest's CommonJS runtime
 * cannot `require` an ES module (it needs Node 24.9+, this project runs Node
 * 22). So the module is tested against its COMPILED output in a child process
 * instead — which is the more honest test anyway, because it exercises the real
 * `require(esm)` interop that the published CLI depends on.
 *
 * The question text is what a developer reads while deciding whether to write
 * model-authored code to a file they are about to commit, so it is worth
 * asserting on directly rather than only through the loop that consumes it.
 *
 * Requires `dist/` — `npm test` builds first.
 */

import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

import { describe, expect, it } from '@jest/globals';

const execFileAsync = promisify(execFile);

const PROMPT_PATH = path.resolve(__dirname, '..', '..', '..', 'dist', 'patch', 'prompt.js');
const BUILT = existsSync(PROMPT_PATH);

if (!BUILT) {
  console.warn(`[prompt e2e] skipped: ${PROMPT_PATH} is not built. Run \`npm run build\` first.`);
}

const QUESTION = {
  candidate: {
    file: 'server/routes/users.js',
    line: 11,
    severity: 'Critical',
    category: 'sql_injection',
    explanation:
      'The id parameter is concatenated straight into the SQL text, so a crafted value can change the query.',
    patch: '@@ -11,2 +11,2 @@\n-  const sql = "…" + userId;\n+  const sql = "… = ?";\n',
  },
  canApply: true,
  edited: false,
  repairs: ['added the missing file header (--- a/server/routes/users.js / +++ b/server/routes/users.js)'],
};

async function runScript(script: string): Promise<{ code: number; output: string }> {
  try {
    const { stdout, stderr } = await execFileAsync('node', ['-e', script], { windowsHide: true });
    return { code: 0, output: `${stdout}${stderr}` };
  } catch (error) {
    const failure = error as { code?: unknown; stdout?: string; stderr?: string };
    return {
      code: typeof failure.code === 'number' ? failure.code : 1,
      output: `${failure.stdout ?? ''}${failure.stderr ?? ''}`,
    };
  }
}

/** Requires the compiled module and prints whatever the expression evaluates to. */
function probe(expression: string, question: unknown = QUESTION): Promise<{ code: number; output: string }> {
  return runScript(
    [
      `const m = require(${JSON.stringify(PROMPT_PATH)});`,
      `const question = ${JSON.stringify(question)};`,
      `process.stdout.write(String(${expression}));`,
    ].join('\n'),
  );
}

const maybe = BUILT ? describe : describe.skip;

maybe('the compiled prompt module', () => {
  it('loads with the real inquirer behind it', async () => {
    // The failure this guards: a CommonJS build `require`-ing an ESM-only
    // package. It works on Node >=22.12, and this is what says so out loud.
    const result = await probe('typeof m.makeAsk');

    expect(result.code).toBe(0);
    expect(result.output).toBe('function');
  });

  it('renders the finding, the explanation, the patch and the repairs', async () => {
    const result = await probe('m.renderQuestion(question, false)');

    expect(result.code).toBe(0);
    expect(result.output).toContain('server/routes/users.js:11');
    expect(result.output).toContain('Critical · sql_injection');
    expect(result.output).toContain('concatenated straight into the SQL text');
    expect(result.output).toContain("patch: the model's patch — 1 hunk");
    // Named in the prompt, not only on stderr when it happened: by the time the
    // developer is choosing, "CodeGuard rewrote this patch's header" is material
    // to whether they trust it.
    expect(result.output).toContain('repaired: added the missing file header');
  });

  it('says the patch is unusable instead of offering one', async () => {
    const result = await probe('m.renderQuestion(question, false)', {
      ...QUESTION,
      canApply: false,
      repairs: [],
      candidate: { ...QUESTION.candidate, patch: 'I could not produce a patch.' },
    });

    expect(result.output).toContain('patch: no usable patch');
    expect(result.output).not.toContain("the model's patch");
  });

  it('explains why there is no patch when the pipeline produced none', async () => {
    const result = await probe('m.renderQuestion(question, false)', {
      ...QUESTION,
      canApply: false,
      repairs: [],
      candidate: {
        ...QUESTION.candidate,
        patch: '',
        reason:
          'deep analysis did not produce a patch for this finding — its answer was discarded or unusable',
      },
    });

    expect(result.output).toContain('patch: no usable patch');
    // The sentence that separates "the model had nothing to offer" from
    // "CodeGuard threw the answer away" — the developer is about to choose
    // between writing a patch by hand and skipping, and that is the difference.
    expect(result.output).toContain('no patch produced: deep analysis did not produce a patch');
  });

  it('marks a question about an edited patch as the developer`s own', async () => {
    const result = await probe('m.renderQuestion(question, false)', { ...QUESTION, edited: true });

    expect(result.output).toContain('patch: your edited patch');
    expect(result.output).not.toContain("the model's patch");
  });

  it('builds an asker and an editor binding without opening anything', async () => {
    // Neither call may touch a TTY or spawn an editor: they only close over the
    // settings, and the prompt happens when the returned function is called.
    const result = await probe(
      "`${typeof m.makeAsk({ writeError() {} })}/${typeof m.makeEdit({ writeError() {} })}`",
    );

    expect(result.code).toBe(0);
    expect(result.output).toBe('function/function');
  });
});
