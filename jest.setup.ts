/**
 * Global test setup: make the suite hermetic.
 *
 * The problem this solves is specific and would otherwise be silent. Since
 * Phase 4, mode detection reads `DEEPSEEK_API_KEY` from the process environment,
 * and the pre-commit end-to-end test spawns the REAL built CLI as a subprocess,
 * which inherits that environment. So on a machine where the developer has
 * exported a key, `npm test` would:
 *
 *   - attempt live API calls and take minutes instead of seconds,
 *   - spend real money on every run,
 *   - and — worst — transmit whatever diff the fixtures contain to a third
 *     party, from a test suite, without anyone asking for it.
 *
 * On a machine without a key none of that happens, so the failure would only
 * appear for some contributors. Deleting the variables here makes every run
 * behave the same way: Local Mode, no network.
 *
 * This deliberately does NOT rely on the tests each remembering to scrub the
 * environment. A guarantee that depends on every future test author knowing
 * about it is not a guarantee.
 */

const PROVIDER_VARIABLES = ['DEEPSEEK_API_KEY', 'CODEGUARD_MODEL'] as const;

for (const name of PROVIDER_VARIABLES) {
  delete process.env[name];
}
