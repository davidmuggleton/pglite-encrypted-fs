import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 120000,
    hookTimeout: 60000,
    maxConcurrency: 1,
    benchmark: {
      include: ['bench/**/*.bench.ts'],
    },
  },
})
