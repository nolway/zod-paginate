# zod-paginate

A small utility to **parse and validate pagination + select + sort + filters** from querystring-like objects using **Zod v4**, and to generate a **response validator** that automatically projects your `dataSchema` based on the requested `select`.

It is designed for Node.js HTTP stacks where query parameters arrive as strings (or string arrays). It outputs a **typed, normalized** structure you can map to your ORM/query builder.

- Supports **LIMIT/OFFSET pagination** (`limit` + `page`).
- Supports **CURSOR pagination** with cursor coercion based on `cursorProperty` (number / string / ISO date string).
- Supports **field projection** using `select`, including wildcard expansion (`*`) when enabled.
- Supports **sorting** with an allowlist of sortable fields.
- Supports a **filter DSL** with `$` operators and **nested AND/OR grouping**.
- Provides a **response validator** (`validatorSchema`) to validate API responses against the projected schema.

> This library does **not** bind DB queries automatically.
> It gives you a safe parsed structure; you decide how to map it to your data layer.

## Installation

```bash
npm i zod-paginate
# or
pnpm add zod-paginate
# or
yarn add zod-paginate
```

## Quick start

```ts
import { z } from "zod";
import { paginate } from "zod-paginate";

const ModelSchema = z.object({
  id: z.number(),
  status: z.string(),
  createdAt: z.date(),
  meta: z.object({
    score: z.number(),
  }),
});

const { queryParamsSchema, validatorSchema } = paginate({
  paginationType: "LIMIT_OFFSET",
  dataSchema: ModelSchema,

  selectable: ["id", "status", "createdAt", "meta.score"],
  sortable: ["createdAt", "id"],
  filterable: {
    status: { type: "string", ops: ["$eq", "$ilike"] },
    createdAt: { type: "date", ops: ["$btw", "$null", "$eq", "$gt", "$lte"] },
    id: { type: "number", ops: ["$gt", "$in", "$eq"] },
    "meta.score": { type: "number", ops: ["$gte", "$lte"] },
  },

  defaultSortBy: [{ property: "createdAt", direction: "DESC" }],
  defaultLimit: 20,
  maxLimit: 100,
  defaultSelect: ["*"],
});

// Example querystring-like input
const parsed = queryParamsSchema.parse({
  limit: "10",
  page: "2",
  sortBy: "createdAt:DESC",
  select: "id,status",
  "filter.status": "$ilike:act",
});

console.log(parsed.pagination);

// Build the response validator from the request context
const responseSchema = validatorSchema(parsed);
```

## API

### `paginate(config)`

Returns:

- `queryParamsSchema`: Zod schema to parse query objects (strings / string arrays).
- `validatorSchema(parsed?)`: function returning a Zod schema to validate the response payload.

```ts
export function paginate<TSchema extends DataSchema>(
  config: QueryConfigFromSchema<TSchema>,
): {
  queryParamsSchema: z.ZodType<PaginationQueryParams<TSchema>>;
  validatorSchema: (parsed?: PaginationQueryParams<TSchema>) => z.ZodType;
}
```

## Configuration (`paginate({...})`)

| Option | Type | Description |
|---|---:|---|
| `paginationType` | `"LIMIT_OFFSET"` \| `"CURSOR"` | Select pagination mode. |
| `dataSchema` | `z.ZodObject` | Zod schema representing one **data item** returned by your API (used for projection + cursor inference). |
| `selectable?` | `string[]` (typed paths) | Allowlist of selectable fields (dot paths supported). Enables `select`. |
| `sortable?` | `string[]` (typed paths) | Allowlist of sortable fields. Enables `sortBy`. |
| `filterable?` | object | Allowlist of filterable fields and allowed operators + field type. |
| `defaultSortBy?` | `{ property, direction }[]` | Default sort if `sortBy` missing/empty. |
| `defaultLimit?` | `number` | Default limit if `limit` missing. |
| `maxLimit?` | `number` | Rejects `limit` values above this. |
| `defaultSelect?` | `("*" \| field)[]` | Default select if `select` missing. `["*"]` expands to `selectable`. |
| `cursorProperty` | (CURSOR only) typed path | The field used for cursor paging. Cursor type is inferred from `dataSchema` at that path and the query input cursor is coerced accordingly. |

## Query input shape

`queryParamsSchema` accepts any record-like input:

```ts
Record<string, unknown>
```

Typical querystring parsers produce values like:

- `"10"` (string)
- `["a", "b"]` (repeated query params)
- everything else is ignored / treated as undefined

## Query parameters

### `limit`

- Input: string numeric (e.g. `"10"`)
- Output: number
- Rules
  - Must be a numeric string
  - Must be `<= maxLimit` if configured
  - Falls back to `defaultLimit` when missing

### `page` (LIMIT_OFFSET only)

- Input: string numeric (e.g. `"2"`)
- Output: number
- Rules
  - Only valid when `paginationType: "LIMIT_OFFSET"`
  - Forbidden in CURSOR mode

### `cursor` (CURSOR only)

- Input: string (querystring input is always string)
- Output: `number | string` (coerced)
- Rules
  - Only valid when `paginationType: "CURSOR"`
  - Forbidden in LIMIT_OFFSET mode
  - If provided, it is coerced based on the Zod type of `cursorProperty` in `dataSchema`:
    - `z.number()` field → `"123"` becomes `123` (integer-only)
    - `z.string()` field → `"abc"` stays `"abc"`
    - `z.date()` field → must be ISO date or ISO datetime, stays a string (`"2022-01-01"` or `"2022-01-01T12:00:00Z"`)

### `sortBy`

- Input: string or string[]
- Output: `[{ property, direction }]`
- Rules
  - Requires `sortable` in config
  - Format: `field:ASC` or `field:DESC`
  - Empty items are ignored
  - If missing (or becomes empty after cleanup), falls back to `defaultSortBy` if configured
  - Properties are matched against the allowlist (unknown fields are dropped)

### `select`

- Input: string
- Output: string[] (typed paths)
- Rules
  - Requires `selectable` in config
  - string is split by `,`, trimmed, empty items removed
  - `*` expands to the configured `selectable` allowlist
  - If missing, falls back to `defaultSelect` if configured
  - `select=` (empty) is rejected
  - Unknown fields are rejected at parse-time (strict allowlist)

## Filters

Filters are passed as query keys with this pattern:

```txt
filter.<field>=<dsl>
```

Where `<field>` is a dot-path field (example: `meta.score`).

You configure which fields are filterable and which operators are allowed via `filterable`.

### Operators

| Operator | Meaning | Value format |
|---|---|---|
| `$eq` | equals | number / string / ISO date depending on field type |
| `$null` | is null | no value |
| `$in` | in list | `a,b,c` (comma-separated) |
| `$contains` | contains values | `a,b,c` (comma-separated) |
| `$gt` | greater than | number or ISO date |
| `$gte` | greater than or equal | number or ISO date |
| `$lt` | less than | number or ISO date |
| `$lte` | less than or equal | number or ISO date |
| `$btw` | between | `a,b` where both are numbers OR both are ISO dates |
| `$ilike` | case-insensitive contains (string) | string |
| `$sw` | starts with (string) | string |

#### `$eq` — equals

Matches rows where the field is exactly equal to the given value. The value type must match the field type (number, string, or ISO date).

```txt
filter.status=$eq:active
filter.id=$eq:42
filter.createdAt=$eq:2025-01-15
```

#### `$null` — is null

Matches rows where the field is `NULL`. No value is required after the operator.

```txt
filter.deletedAt=$null
```

To match rows where the field is **not** null, combine with `$not`:

```txt
filter.deletedAt=$not:$null
```

#### `$in` — in list

Matches rows where the field value is one of the provided comma-separated values.

```txt
filter.status=$in:active,pending,review
filter.id=$in:1,2,3,10
```

#### `$contains` — contains values

Matches rows where the field (typically an array column) contains all the provided comma-separated values.

```txt
filter.tags=$contains:typescript,zod
filter.roles=$contains:admin
```

#### `$gt` / `$gte` / `$lt` / `$lte` — comparisons

Standard comparison operators: greater than, greater than or equal, less than, less than or equal. Works with numbers and ISO dates.

```txt
filter.id=$gt:100
filter.id=$lte:500
filter.createdAt=$gte:2025-01-01
filter.createdAt=$lt:2025-06-01T00:00:00Z
```

Combine multiple comparisons to build ranges:

```txt
filter.id=$gt:10&filter.id=$lt:100
```

#### `$btw` — between

Matches rows where the field value falls between two bounds (inclusive). Both bounds must be the same type — either both numbers or both ISO dates.

```txt
filter.id=$btw:10,100
filter.createdAt=$btw:2025-01-01,2025-12-31
filter.createdAt=$btw:2025-01-01T00:00:00Z,2025-06-30T23:59:59Z
```

#### `$ilike` — case-insensitive contains

Matches rows where the string field contains the given substring, ignoring case. Useful for search-style filtering.

```txt
filter.status=$ilike:act
filter.name=$ilike:john
filter.email=$ilike:@example.com
```

#### `$sw` — starts with

Matches rows where the string field starts with the given prefix.

```txt
filter.name=$sw:Jon
filter.email=$sw:admin@
filter.path=$sw:/api/v2
```

Runtime validation enforces:

1) field allowlist (`filterable`)
2) operator allowlist per field (`ops`)
3) value type compatibility (number vs date vs string)

### Default operator: `$eq`

If the filter does **not** start with `$`, it is interpreted as `$eq:<value>`.

### Negation: `$not`

Prefix any operator with `$not:` to negate the condition.

Examples:

```txt
filter.createdAt=$not:$null
filter.status=$not:$eq:active
```

### Multiple conditions for the same field

Use repeated query params:

```txt
filter.id=$gt:10&filter.id=$lt:100
```

Or in object form:

```ts
{
  "filter.id": ["$gt:10", "$lt:100"]
}
```

## Groups

Groups let you build nested AND/OR boolean logic.

There are two layers:

1) Combine multiple conditions inside the same group
2) Build a group tree (attach groups as children of other groups)

### Put a condition into a group: `$g:<id>`

Prefix any filter DSL with:

```txt
$g:<groupId>:
```

### Combine conditions inside a group: `$and` / `$or`

Within a group, the **first** condition cannot have `$and`/`$or`. All following conditions may be prefixed with `$and` or `$or`.

### Group tree definitions: `group.<id>.*`

To nest groups, define these query keys:

- `group.<id>.parent` — parent group id (integer string)
- `group.<id>.join` — how this group is joined to its parent (`$and` or `$or`)
- `group.<id>.op` — default join used when combining this group's children (optional)

Rules:

- Root group id is always `"0"`.
- `group.0.parent` and `group.0.join` are forbidden.
- Cycles are rejected.
- Child groups are resolved in numeric order (deterministic).

## Validating responses with `validatorSchema()`

`validatorSchema(parsed)` returns a Zod schema you can use to validate your API response.

What it does:

- Uses the effective `select` (explicit `select`, else `defaultSelect`, else full schema) to project the item schema.
- Validates cursor type (CURSOR mode) based on `cursorProperty`.
- Enforces mode-specific pagination metadata shape.

### What `validatorSchema(parsed)` expects

**LIMIT/OFFSET mode**:

```ts
{
  data: Array<ProjectedItem>,
  pagination: {
    itemsPerPage: number,
    totalItems: number,
    currentPage: number,
    totalPages: number,
    sortBy?: Array<{ property: string, direction: "ASC" | "DESC" }>,
    filter?: WhereNode
  }
}
```

**CURSOR mode**:

```ts
{
  data: Array<ProjectedItem>,
  pagination: {
    itemsPerPage: number,
    cursor: number | string | Date,
    sortBy?: Array<{ property: string, direction: "ASC" | "DESC" }>,
    filter?: WhereNode
  }
}
```

Notes:

- `ProjectedItem` is computed from `dataSchema` + the effective `select`.
- If `cursorProperty` points to a `z.number()` field, `pagination.cursor` must be a number.
- If `cursorProperty` points to a `z.string()` field, `pagination.cursor` must be a string.
- If `cursorProperty` points to a `z.date()` field, this library accepts an ISO string or a `Date` (depending on implementation).

You can call `validatorSchema()` without arguments to build a validator based on defaults (`defaultSelect`, `cursorProperty`, etc.).

## End-to-end examples

### Example 1 — LIMIT/OFFSET

HTTP query:

```txt
?limit=20&page=1&select=id,status,createdAt&sortBy=createdAt:DESC&filter.status=$ilike:act&filter.id=$gt:10
```

Parsing:

```ts
const parsed = queryParamsSchema.parse({
  limit: "20",
  page: "1",
  select: "id,status,createdAt",
  sortBy: "createdAt:DESC",
  "filter.status": "$ilike:act",
  "filter.id": "$gt:10",
});

// parsed.pagination
// {
//   type: "LIMIT_OFFSET",
//   limit: 20,
//   page: 1,
//   select: ["id", "status", "createdAt"],
//   sortBy: [{ property: "createdAt", direction: "DESC" }],
//   filters: { type: "and", items: [...] } // WhereNode AST
// }
```

### Example 2 — CURSOR + coercion

Config:

```ts
const { queryParamsSchema } = paginate({
  paginationType: "CURSOR",
  dataSchema: ModelSchema,
  cursorProperty: "id", // id is z.number()
  selectable: ["id", "status", "createdAt"],
  defaultSelect: ["id", "createdAt"],
});
```

Parsing:

```ts
const parsed = queryParamsSchema.parse({ cursor: "123", limit: "10" });

// parsed.pagination
// {
//   type: "CURSOR",
//   limit: 10,
//   cursor: 123,            // <- coerced from "123" because cursorProperty is a number
//   cursorProperty: "id",
//   select: ["id", "createdAt"]
// }
```

### Example 3 — groups

Goal: `(status == active OR status == postponed) AND (id > 10)`

```ts
const parsed = queryParamsSchema.parse({
  "filter.status": ["$g:1:$eq:active", "$g:1:$or:$eq:postponed"],
  "filter.id": "$g:2:$gt:10",

  "group.1.parent": "0",
  "group.2.parent": "0",
  "group.2.join": "$and",
});

// parsed.pagination.filters
// {
//   type: "and",
//   items: [
//     { type: "or", items: [ ...status filters... ] },
//     { type: "filter", field: "id", condition: { op: "$gt", value: 10, ... } }
//   ]
// }
```

### Example 4 — validating your response

```ts
const parsed = queryParamsSchema.parse({ select: "id,status", limit: "10", page: "1" });
const responseSchema = validatorSchema(parsed);

// responseSchema expects:
// - data items shaped like { id: number, status: string }
// - pagination metadata for LIMIT/OFFSET

responseSchema.parse({
  data: [{ id: 1, status: "active" }],
  pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
});
```
