import { defineConfig } from 'vitest/config';

// Coverage is a RATCHET, not a target. Thresholds sit just under today's numbers, so a
// change that drops coverage fails CI while a change that raises it does not need the
// file touched. Raise these when coverage rises; never lower them to make CI pass.
export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      // Measure the library, not the tests. Counting test files inflates the number to
      // the point where the gate stops meaning anything.
      include: ['src/**/*.ts'],
      // index.ts is re-exports and types.ts is types — neither has statements to run,
      // and counting them as 0% would make the whole-project number meaningless.
      exclude: ['src/index.ts', 'src/types.ts', 'dist/**', '**/*.config.ts'],
      thresholds: {
        // Measured with vitest 5 (and 4 before it), whose v8 provider remaps by AST and so
        // counts an early `return` or a one-line `throw` as a statement of its own. At 0.4.0: 99.78
        // statements, 96.26 branches, 100 functions, 99.86 lines. The residual gap is
        // defensive code unreachable on validated input (a re-check of what the
        // declaration check already refused). Floors sit a little under the numbers so a
        // Node minor version does not trip them.
        statements: 99,
        branches: 95,
        functions: 100,
        lines: 99,
      },
    },
  },
});
