const tseslint = require('@typescript-eslint/eslint-plugin');

/** @type {import('eslint').Linter.FlatConfig[]} */
module.exports = [
  { ignores: ['dist/**', 'node_modules/**', 'coverage/**'] },
  ...tseslint.configs['flat/recommended-type-checked'],
  {
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.json'],
        tsconfigRootDir: __dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      // shared is a pure library — no stdout/stderr output belongs here.
      'no-console': 'error',
    },
  },
];
