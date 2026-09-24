/**
 * Jest configuration.
 *
 * The transformer is @swc/jest, not ts-jest: ts-jest drives the TypeScript
 * compiler's internal API and its peer range is `typescript >=4.3 <7`, so it
 * cannot run against this project's TypeScript 7. @swc/jest transpiles with SWC
 * instead — a separate implementation that only *strips* types, so it is
 * indifferent to the installed TypeScript version.
 *
 * The trade-off is that tests are not type-checked as they run. That is why the
 * `test` npm script runs `tsc -p tsconfig.test.json` first: a type error still
 * fails the test command, it just fails in a separate, explicit step. That config
 * re-includes `*.test.ts`, which the build config excludes — without it, tests
 * would be transpiled by SWC and never type-checked at all.
 *
 * @type {import('jest').Config}
 */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': [
      '@swc/jest',
      {
        jsc: {
          parser: { syntax: 'typescript' },
          target: 'es2022',
        },
        // Emit CommonJS so tests are require()-able and match the build output.
        module: { type: 'commonjs' },
      },
    ],
  },
  clearMocks: true,
};
