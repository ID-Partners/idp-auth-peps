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
        // Functions and per-file lines are held at 100 where reached; the residual
        // statement/branch gap is defensive code unreachable on validated input
        // (an object-claim that is not an object, AST fall-through the compiler rules
        // out). Floors sit at the current numbers and ratchet up as that shrinks.
        statements: 97,
        branches: 90,
        functions: 100,
        lines: 97,
      },
    },
  },
});
