import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'

const __dirname = dirname(fileURLToPath(import.meta.url))

export default tseslint.config(
  {
    ignores: ['dist', 'node_modules'],
  },

  js.configs.recommended,

  ...tseslint.configs.recommendedTypeChecked.map((config) => ({
    ...config,
    files: ['src/**/*.ts'],
    languageOptions: {
      ...config.languageOptions,
      parserOptions: {
        ...config.languageOptions?.parserOptions,
        project: './tsconfig.json',
        tsconfigRootDir: __dirname,
      },
    },
  })),

  {
    files: ['src/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': ['warn', { ignoreRestArgs: true }],
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-inferrable-types': 'off',
      '@typescript-eslint/no-empty-function': 'off',
      '@typescript-eslint/ban-ts-comment': [
        'error',
        { 'ts-ignore': 'allow-with-description' },
      ],
      '@typescript-eslint/consistent-type-imports': 'warn',
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'no-constant-condition': ['error', { checkLoops: false }],
      eqeqeq: ['error'],
    },
  },
)
