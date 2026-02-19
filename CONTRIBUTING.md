# Contributing

Thanks for taking the time to contribute.

## Getting started

- Fork the repo and create a branch from `main`.
- Install dependencies with `npm install` (or `pnpm install`, `yarn`).
- Make your changes with a focused scope and clear commit history.

## Development scripts

- `npm run lint` - Run ESLint.
- `npm run lint:fix` - Fix lint issues where possible.
- `npm run typecheck` - TypeScript typecheck.
- `npm run test` - Run unit tests.
- `npm run build` - Build the package.

## Commit messages

This project uses Conventional Commits via commitlint. Example:

- `feat: add cursor coercion for bigint`
- `fix: handle empty select parameter`
- `docs: clarify filter operators`

## Pull requests

- Keep PRs small and focused.
- Update docs and examples when behavior changes.
- Include tests for bug fixes and new features when possible.
- Ensure `npm run lint`, `npm run typecheck`, and `npm run test` pass.

## Reporting bugs

Please use the bug report issue template and include:

- Steps to reproduce
- Expected vs actual behavior
- Node version and package manager
- Minimal repro if possible

## Requesting features

Use the feature request template and explain the use case and expected API.
