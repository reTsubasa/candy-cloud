import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist', 'coverage'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/no-explicit-any': 'off',
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.object.name='Modal'][callee.property.name=/^(confirm|info|warning|error|success)$/]",
          message: 'Use a controlled Modal component; Arco static modals are incompatible with React 19.',
        },
        {
          selector: "CallExpression[callee.object.name='Message'][callee.property.name=/^(success|error|warning|info|normal)$/]",
          message: 'Use Message.useMessage() with its context holder; Arco static messages are incompatible with React 19.',
        },
      ],
    },
  },
);
