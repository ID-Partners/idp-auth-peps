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
        statements: 81,
        branches: 73,
        functions: 90,
        lines: 81,
      },
    },
  },
});
