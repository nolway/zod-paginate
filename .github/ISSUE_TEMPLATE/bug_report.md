---
name: Bug report
about: Report a bug or regression
labels: bug
---

Please fill in the sections below so we can reproduce and fix the issue quickly.

## What is the bug?

Briefly describe what is wrong.

## Expected vs actual

- Expected:
- Actual:

## Repro steps

If you can share a minimal repro repository or snippet, link it here:

- Repro link:

## Minimal config and input

Paste the smallest config that still reproduces the issue:

```ts
// paginate({ ... })
```

Input example (querystring or object):

```txt
// filter.status=$eq:active&limit=10
```

## Error output (if any)

```txt
// stack trace or error output
```

## Environment

- OS:
- Node version:
- Package manager:
- zod-paginate version:
- zod version:

## Scope

- [ ] Regression (worked in a previous version)
- [ ] Only affects CURSOR mode
- [ ] Only affects LIMIT/OFFSET mode
- [ ] Only affects filters/operators

## Additional notes

Workarounds, related issues, or anything else useful.

