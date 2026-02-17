// @ts-check
import eslint from '@eslint/js';
import eslintPluginPrettierRecommended from 'eslint-plugin-prettier/recommended';
import tseslint from 'typescript-eslint';
import * as importPlugin from 'eslint-plugin-import';
import stylistic from '@stylistic/eslint-plugin';
import eslintPluginPrettier from 'eslint-plugin-prettier';
import checkFile from 'eslint-plugin-check-file';
import noOnlyTestsPlugin from 'eslint-plugin-no-only-tests';
import eslintConfigPrettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    ignores: [
      'eslint.config.mjs',
      'eslint.service.config.mjs',
      'lint-staged.config.mjs',
      '.prettierrc.mjs',
      'commitlint.config.mjs',
      'vitest.config.mjs',
    ],
  },
  eslint.configs.recommended,
  tseslint.configs.strictTypeChecked,
  tseslint.configs.stylisticTypeChecked,
  eslintPluginPrettierRecommended,
  {
    extends: [
      importPlugin.flatConfigs?.recommended,
      importPlugin.flatConfigs?.warnings,
      importPlugin.flatConfigs?.errors,
      importPlugin.flatConfigs?.typescript,
    ],
    plugins: {
      '@stylistic': stylistic,
      prettier: eslintPluginPrettier,
      'check-file': checkFile,
      'no-only-tests': noOnlyTestsPlugin,
    },
    languageOptions: {
      sourceType: 'module',
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    settings: {
      'import/resolver': {
        typescript: {
          alwaysTryTypes: true,
        },
      },
    },
  },
  {
    rules: {
      'no-throw-literal': 'error',
      'no-async-promise-executor': 'error',
      'no-await-in-loop': 'error',
      'no-promise-executor-return': 'error',
      'require-atomic-updates': 'error',
      'prefer-promise-reject-errors': 'error',
      'no-restricted-imports': [
        'error',
        {
          patterns: ['**/*.test.ts', '**/*.test.*.ts'],
        },
      ],
      'no-nested-ternary': 'error',
      'prettier/prettier': [
        'error',
        {},
        {
          usePrettierrc: true,
        },
      ],
      'check-file/filename-naming-convention': [
        'error',
        {
          'src/**/*.{ts,json}': '+([a-z0-9])*([.-]([a-z0-9])+)',
          'src/enums/**/*.ts': '@(+([a-z0-9])*([.-]([a-z0-9])+).enum|index)',
          'src/errors/**/*.ts': '@(+([a-z0-9])*([.-]([a-z0-9])+).error|index)',
          'src/services/**/*.ts':
            '@(+([a-z0-9])*([.-]([a-z0-9])+).service(.test)?|index)',
          'src/types/**/*.ts': '@(+([a-z0-9])*([.-]([a-z0-9])+).type|index)',
          'src/utils/**/*.ts':
            '@(+([a-z0-9])*([.-]([a-z0-9])+).util(.test)?|index)',
        },
      ],
      'check-file/folder-naming-convention': [
        'error',
        { 'src/**/': '+([a-z0-9])*([.-]([a-z0-9])+)' },
      ],
      '@stylistic/eol-last': 'error',
      '@stylistic/no-tabs': 'error',
      'import/order': [
        'error',
        {
          groups: ['builtin', 'external', 'internal', 'parent', 'sibling', 'index'],
          pathGroups: [
            {
              pattern: 'src/**',
              group: 'internal',
            },
          ],
          pathGroupsExcludedImportTypes: ['builtin'],
          alphabetize: {
            order: 'asc',
            caseInsensitive: true,
          },
          'newlines-between': 'never',
        },
      ],
      'no-only-tests/no-only-tests': 'error',
      '@typescript-eslint/require-await': 'error',
      '@typescript-eslint/explicit-function-return-type': 'error',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/restrict-template-expressions': 'off',
      '@typescript-eslint/no-misused-spread': 'off',
      '@typescript-eslint/no-unsafe-return': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unnecessary-type-assertion': 'error',
      '@typescript-eslint/no-unsafe-argument': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/no-unnecessary-condition': 'error',
      '@typescript-eslint/consistent-type-assertions': [
        'error',
        {
          assertionStyle: 'never',
        },
      ],
      '@typescript-eslint/no-unsafe-call': 'error',
      '@typescript-eslint/restrict-plus-operands': 'error',
      '@typescript-eslint/ban-ts-comment': 'error',
      '@typescript-eslint/no-extraneous-class': [
        'error',
        {
          allowEmpty: true,
        },
      ],
      '@typescript-eslint/consistent-type-definitions': 'error',
      '@typescript-eslint/consistent-indexed-object-style': 'error',
      '@typescript-eslint/consistent-generic-constructors': 'error',
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/naming-convention': [
        'error',
        {
          selector: 'interface',
          format: ['PascalCase'],
        },
        {
          selector: 'typeAlias',
          format: ['PascalCase'],
        },
        {
          selector: 'typeMethod',
          format: ['camelCase'],
        },
        {
          selector: 'enum',
          format: ['PascalCase'],
        },
        {
          selector: 'enumMember',
          format: ['UPPER_CASE'],
        },
        {
          selector: 'class',
          format: ['PascalCase'],
        },
        {
          selector: 'classMethod',
          format: ['camelCase'],
        },
        {
          selector: 'classProperty',
          format: ['camelCase'],
        },
        {
          selector: 'function',
          format: ['camelCase'],
        },
        {
          selector: 'parameter',
          format: ['camelCase'],
        },
        {
          selector: 'parameterProperty',
          format: ['camelCase'],
        },
      ],
    },
  },
  {
    files: ['**/*.test.ts', '**/*.test.*.ts'],
    rules: {
      'no-restricted-imports': 'off',
    },
  },
  {
    files: ['**/*.d.ts'],
    rules: {
      '@typescript-eslint/consistent-type-definitions': 'off',
    },
  },
  eslintConfigPrettier,
);
