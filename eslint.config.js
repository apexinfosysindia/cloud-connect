const js = require('@eslint/js');
const globals = require('globals');
const eslintConfigPrettier = require('eslint-config-prettier');

module.exports = [
    // Ignore patterns
    {
        ignores: ['node_modules/', 'public/']
    },

    // Base recommended rules for all JS files
    js.configs.recommended,

    // Node.js server configuration
    {
        files: ['**/*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: {
                ...globals.node
            }
        },
        rules: {
            // Error prevention
            'no-unused-vars': [
                'warn',
                {
                    argsIgnorePattern: '^_',
                    varsIgnorePattern: '^_',
                    caughtErrorsIgnorePattern: '^_'
                }
            ],
            'no-undef': 'error',
            'no-constant-condition': ['error', { checkLoops: false }],
            'no-empty': ['error', { allowEmptyCatch: true }],

            // Best practices
            eqeqeq: ['error', 'always', { null: 'ignore' }],
            'no-var': 'error',
            'prefer-const': ['warn', { destructuring: 'all' }],
            'no-throw-literal': 'error',
            'no-return-await': 'off', // return await is useful for stack traces; conflicts with require-await
            'require-await': 'warn',
            'no-async-promise-executor': 'error',
            'no-promise-executor-return': 'error',

            // Style (non-formatting -- formatting is handled by Prettier)
            'no-lonely-if': 'warn',
            'prefer-template': 'off', // Codebase uses both styles intentionally
            'object-shorthand': ['warn', 'properties'],
            'no-else-return': ['warn', { allowElseIf: true }],

            // Disabled: handled by Prettier or not applicable
            'no-mixed-spaces-and-tabs': 'off',
            indent: 'off',
            semi: 'off',
            quotes: 'off'
        }
    },

    // Disable formatting rules that conflict with Prettier
    eslintConfigPrettier,

    // Test-specific overrides: mock async functions don't need await
    {
        files: ['test/**/*.js'],
        rules: {
            'require-await': 'off'
        }
    }
];
