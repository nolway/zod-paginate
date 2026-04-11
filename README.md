# zod-paginate

![Coverage](https://img.shields.io/badge/coverage-94.26%25-brightgreen)

A small utility to **parse and validate pagination + select + sort + filters** from querystring-like objects using **Zod v4**, and to generate a **response validator** that automatically projects your `dataSchema` based on the requested `select`.

It is designed for Node.js HTTP stacks where query parameters arrive as strings (or string arrays). It outputs a **typed, normalized** structure you can map to your ORM/query builder.

> This library does **not** bind DB queries automatically.
> It gives you a safe parsed structure; you decide how to map it to your data layer.

### Features

- **Field projection** using `select`, including wildcard expansion (`*`).
- **LIMIT/OFFSET pagination** (`limit` + `page`).
- **CURSOR pagination** with cursor coercion based on `cursorProperty` (number / string / ISO date string).
- **Sorting** with an allowlist of sortable fields.
- **Filter DSL** with `$` operators and **nested AND/OR grouping**.
- **Response validation** — `responseSchema` is a generic schema covering all possible responses based on your config; `validatorSchema(parsed.select)` validates outgoing data projected to the actual requested `select`. `z.infer<typeof responseSchema>` gives you **key autocompletion** narrowed to configured `selectable` paths.
- **Discriminated union support** — `z.discriminatedUnion()` and `z.union()` as `dataSchema`, with compile-time and runtime discriminator enforcement.
- **Standalone `select()`** utility for field-projection-only use cases.
- Compatible with **OpenAPI tooling** ([zod-openapi](https://github.com/samchungy/zod-openapi) etc.).

## Installation

```bash
npm i zod-paginate
# or
pnpm add zod-paginate
# or
yarn add zod-paginate
```

## Quick start

### Field projection with `select()`

```ts
import { z } from "zod";
import { select } from "zod-paginate";

const ProductSchema = z.object({
  id: z.number(),
  name: z.string(),
  price: z.number(),
});

const { queryParamsSchema, validatorSchema, responseSchema } = select({
  dataSchema: ProductSchema,
  selectable: ["id", "name", "price"],
  defaultSelect: ["id", "name"],
});

const parsed = queryParamsSchema().parse({ select: "id,name,price" });
// parsed.select.fields → ["id", "name", "price"]

// Generic response schema — valid for all possible responses based on config
responseSchema.parse({
  data: [{ id: 1, name: "Widget" }],
});

// Outgoing data validator — projected to the actual requested select
const contextSchema = validatorSchema(parsed.select);
contextSchema.parse({
  data: [{ id: 1, name: "Widget", price: 9.99 }],
});
```

### Full pagination with `paginate()`

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

const { queryParamsSchema, validatorSchema, responseSchema } = paginate({
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
  defaultSelect: '*',
});

const parsed = queryParamsSchema().parse({
  limit: "10",
  page: "2",
  sortBy: "createdAt:DESC",
  select: "id,status",
  "filter.status": "$ilike:act",
});

console.log(parsed.pagination);

// Generic response schema — valid for all possible responses based on config
responseSchema.parse({
  data: [{ id: 1, status: "active", createdAt: new Date(), meta: { score: 42 } }],
  pagination: { itemsPerPage: 20, totalItems: 1, currentPage: 1, totalPages: 1 },
});

// Outgoing data validator — projected to the actual requested select
const contextSchema = validatorSchema(parsed.pagination);
contextSchema.parse({
  data: [{ id: 1, status: "active" }],
  pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
});
```

## Summary

- [select() API](#select)
  - [SelectConfig](#selectconfig)
  - [responseType: 'one'](#responsetype-one)
- [paginate() API](#paginate)
  - [PaginateConfig](#paginateconfig)
  - [PaginateResult](#paginateresulttschema-tselectable-ttype)
- [Query parameters](#query-parameters)
  - [limit](#limit) · [page](#page-limit_offset-only) · [cursor](#cursor-cursor-only) · [sortBy](#sortby) · [select](#select-1)
- [Response validation](#response-validation)
- [Filters](#filters)
  - [Operators](#operators) · [Negation](#negation-not) · [Multiple conditions](#multiple-conditions-for-the-same-field)
- [Filter groups](#filter-groups)
- [Discriminated unions](#discriminated-unions)
  - [Compile-time enforcement](#compile-time-enforcement-on-selectable) · [Runtime enforcement](#runtime-rejection-of-explicit-select-without-discriminator) · [Union-preserving validation](#union-preserving-response-validation)
- [Extending queryParamsSchema](#extending-queryparamsschema)
- [End-to-end examples](#end-to-end-examples)
- [TypeScript reference](#typescript-reference)
- [Adapters](#adapters)

## `select()`

Standalone **field projection** utility. Use it when you only need to parse a `select` query parameter and validate the response — no pagination, sorting, or filters.

```ts
import { select } from "zod-paginate";
```

Returns:

| Property | Description |
|---|---|
| `queryParamsSchema(extraShape?)` | Zod schema to parse `{ select: "id,name" }` into `{ select: ["id", "name"] }`. |
| `validatorSchema(parsed?)` | Validates outgoing data projected to the actual requested `select`. Shape: `{ data: ProjectedItem[] }` (or `{ data: ProjectedItem }` when `responseType: 'one'`). |
| `responseSchema` | Generic `ZodObject` covering all possible responses based on your config. `z.infer<typeof responseSchema>` narrows data keys to `selectable` paths. |

### `SelectConfig`

| Option | Type | Description |
|---|---:|---|
| `dataSchema` | `z.ZodObject` \| `z.ZodDiscriminatedUnion` \| `z.ZodUnion` | Zod schema representing one data item. |
| `selectable` | `string[]` (typed paths) | Allowlist of selectable fields (dot paths supported). |
| `defaultSelect` | `field[] \| "*"` | **Required.** Default when `select` is missing. `"*"` expands to `selectable`. |
| `responseType` | `"many" \| "one"` | Shape of `data` in the response (default: `"many"`). |

#### Example

```ts
import { z } from "zod";
import { select } from "zod-paginate";

const ProductSchema = z.object({
  id: z.number(),
  name: z.string(),
  price: z.number(),
  details: z.object({
    weight: z.number(),
    color: z.string(),
  }),
});

const { queryParamsSchema, validatorSchema, responseSchema } = select({
  dataSchema: ProductSchema,
  selectable: ["id", "name", "price", "details.weight", "details.color"],
  defaultSelect: ["id", "name", "price"],
});

// select=* expands to all selectable fields
const parsed = queryParamsSchema().parse({ select: "*" });
// parsed.select.fields → ["id", "name", "price", "details.weight", "details.color"]

// Specific fields
const parsed2 = queryParamsSchema().parse({ select: "id,name,details.color" });
// parsed2.select.fields → ["id", "name", "details.color"]

// Generic response schema (based on defaultSelect)
responseSchema.parse({
  data: [{ id: 1, name: "Widget", price: 9.99 }],
});

// Outgoing data validator projected to the actual requested select
const contextSchema = validatorSchema(parsed2.select);
contextSchema.parse({
  data: [
    { id: 1, name: "Widget", details: { color: "red" } },
    { id: 2, name: "Gadget", details: { color: "blue" } },
  ],
});

// Missing select → uses defaultSelect
const parsed3 = queryParamsSchema().parse({});
// parsed3.select.fields → ["id", "name", "price"]
```

Use `SelectResult<TSchema, TSelectable>` instead of `ReturnType<typeof select>` for explicit return types:

```ts
import { select, type SelectResult } from "zod-paginate";

function createSelector(): SelectResult<typeof ProductSchema, "id" | "name" | "price"> {
  return select({ dataSchema: ProductSchema, selectable: ["id", "name", "price"], /* … */ });
}
```

### `responseType: 'one'`

By default, `select()` validates `data` as an array. Pass `responseType: 'one'` to validate a single item instead:

```ts
const { responseSchema } = select({
  dataSchema: ProductSchema,
  selectable: ["id", "name", "price"],
  defaultSelect: ["id", "name"],
  responseType: "one",
});

// Single object → valid
responseSchema.parse({ data: { id: 1, name: "Widget" } });

// Array → rejected
responseSchema.parse({ data: [{ id: 1 }] }); // throws
```

## `paginate()`

Full pagination, sorting, filtering, and field projection. Extends everything `select()` does with pagination support.

```ts
import { paginate } from "zod-paginate";
```

Returns:

| Property | Description |
|---|---|
| `queryParamsSchema(extraShape?)` | Zod schema to parse query objects (strings / string arrays). |
| `validatorSchema(parsed?)` | Validates outgoing data projected to the actual requested `select`. |
| `responseSchema` | Generic `ZodObject` covering all possible responses based on your config. `z.infer<typeof responseSchema>` narrows both data keys and pagination metadata. |

### `PaginateConfig`

| Option | Type | Description |
|---|---:|---|
| `paginationType` | `"LIMIT_OFFSET"` \| `"CURSOR"` | Pagination mode. |
| `dataSchema` | `z.ZodObject` \| `z.ZodDiscriminatedUnion` \| `z.ZodUnion` | Zod schema for one data item (used for projection + cursor inference). |
| `selectable` | `string[]` (typed paths) | **Required.** Allowlist of selectable fields (dot paths). Enables `select`. |
| `sortable?` | `string[]` (typed paths) | Allowlist of sortable fields. Enables `sortBy`. |
| `filterable?` | object | Allowlist of filterable fields and allowed operators + field type. |
| `defaultSortBy?` | `{ property, direction }[]` | Default sort if `sortBy` missing/empty. |
| `defaultLimit` | `number` | **Required.** Default limit if `limit` missing. |
| `maxLimit` | `number` | **Required.** Rejects `limit` values above this. |
| `defaultSelect` | `field[] \| "*"` | **Required.** Default select if `select` missing. `"*"` expands to `selectable`. |
| `cursorProperty` | (CURSOR only) typed path | Field used for cursor paging. Cursor type is inferred from `dataSchema`. |

### `PaginateResult<TSchema, TSelectable?, TType?>`

Use `PaginateResult<TSchema, TSelectable, TType>` instead of `ReturnType<typeof paginate>` when you need an explicit return type — it preserves the generics so that `z.infer<typeof responseSchema>` correctly narrows both data keys and pagination metadata.

**`TType`** (`'LIMIT_OFFSET' | 'CURSOR'`): When specified, narrows the response types so you get `totalItems`/`totalPages` (LIMIT_OFFSET) or `cursor` (CURSOR) without manual narrowing.

```ts
import { paginate, type PaginateResult } from "zod-paginate";

function createPaginator(): PaginateResult<typeof ModelSchema, "id" | "status", "LIMIT_OFFSET"> {
  return paginate({
    paginationType: "LIMIT_OFFSET",
    dataSchema: ModelSchema,
    selectable: ["id", "status"],
    /* … */
  });
}

// Without TType — pagination metadata is a union, but data keys are still narrowed
function createPaginatorUnion(): PaginateResult<typeof ModelSchema, "id" | "status"> {
  return paginate({ dataSchema: ModelSchema, selectable: ["id", "status"], /* … */ });
}
```

## Query parameters

`queryParamsSchema()` accepts any `Record<string, unknown>` input. Typical querystring parsers produce `"10"` (string) or `["a", "b"]` (repeated params).

### `limit`

- **Input:** string numeric (e.g. `"10"`)
- **Output:** number
- Must be `<= maxLimit`; falls back to `defaultLimit` when missing.

### `page` (LIMIT_OFFSET only)

- **Input:** string numeric (e.g. `"2"`)
- **Output:** number
- Only valid when `paginationType: "LIMIT_OFFSET"`. Forbidden in CURSOR mode.

### `cursor` (CURSOR only)

- **Input:** string
- **Output:** `number | string` (coerced)
- Coerced based on the Zod type of `cursorProperty` in `dataSchema`:

| `cursorProperty` type | Input | Output |
|---|---|---|
| `z.number()` | `"123"` | `123` (integer) |
| `z.string()` | `"abc"` | `"abc"` |
| `z.date()` | `"2022-01-01"` | `"2022-01-01"` (ISO string) |

### `sortBy`

- **Input:** string or string[] — format: `field:ASC` or `field:DESC`
- **Output:** `[{ property, direction }]`
- Properties are matched against the `sortable` allowlist (unknown fields are **rejected**).
- Falls back to `defaultSortBy` when missing.

### `select`

- **Input:** comma-separated string (e.g. `"id,name,meta.score"`)
- **Output:** string[] (typed paths)
- `*` expands to the `selectable` allowlist.
- Falls back to `defaultSelect` when missing.
- `select=` (empty) is rejected. Unknown fields are rejected (strict allowlist).

## Response validation

Both `select()` and `paginate()` return tools to validate your API response.

### `responseSchema` — generic response schema

Covers all possible responses based on your config (uses `defaultSelect` or all selectable fields). Ideal for OpenAPI schema generation, static validation, or type inference:

```ts
const { responseSchema } = paginate({
  paginationType: "LIMIT_OFFSET",
  dataSchema: ModelSchema,
  selectable: ["id", "status", "createdAt", "meta.score"],
  defaultSelect: '*',
  defaultLimit: 20,
  maxLimit: 100,
});

responseSchema.parse({
  data: [{ id: 1, status: "active", createdAt: new Date(), meta: { score: 42 } }],
  pagination: { itemsPerPage: 20, totalItems: 1, currentPage: 1, totalPages: 1 },
});

// Type-safe: z.infer narrows data keys to selectable paths
type Response = z.infer<typeof responseSchema>;
// Response["data"][0] → { id?: number; status?: string; createdAt?: Date; meta?: { score: number } }
// Response["pagination"].totalItems → number  ✓ (no manual narrowing)
```

### `validatorSchema(parsed?)` — outgoing data validator

Validates outgoing data projected to the actual `select` requested by the client:

```ts
const parsed = queryParamsSchema().parse({ select: "id,status", limit: "10", page: "1" });
const contextSchema = validatorSchema(parsed.pagination);

contextSchema.parse({
  data: [{ id: 1, status: "active" }],
  pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
});
```

### Expected response shape

**LIMIT/OFFSET:**

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

**CURSOR:**

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

## Filters

Filters use query keys with the pattern `filter.<field>=<dsl>` where `<field>` is a dot-path (e.g. `meta.score`). Configure which fields and operators are allowed via the `filterable` option.

### Operators

| Operator | Meaning | Value format | Example |
|---|---|---|---|
| `$eq` | equals | number / string / ISO date | `filter.status=$eq:active` |
| `$null` | is null | _(no value)_ | `filter.deletedAt=$null` |
| `$in` | in list | comma-separated | `filter.status=$in:active,pending` |
| `$contains` | contains values | comma-separated | `filter.tags=$contains:typescript,zod` |
| `$gt` | greater than | number or ISO date | `filter.id=$gt:100` |
| `$gte` | greater than or equal | number or ISO date | `filter.createdAt=$gte:2025-01-01` |
| `$lt` | less than | number or ISO date | `filter.id=$lt:500` |
| `$lte` | less than or equal | number or ISO date | `filter.id=$lte:500` |
| `$btw` | between (inclusive) | `a,b` (same type) | `filter.id=$btw:10,100` |
| `$ilike` | case-insensitive contains | string | `filter.name=$ilike:john` |
| `$sw` | starts with | string | `filter.name=$sw:Jon` |

If the filter value does **not** start with `$`, it is interpreted as `$eq:<value>`.

### Negation: `$not`

Prefix any operator with `$not:` to negate the condition:

```txt
filter.deletedAt=$not:$null
filter.status=$not:$eq:active
```

### Multiple conditions for the same field

Use repeated query params or pass an array:

```txt
filter.id=$gt:10&filter.id=$lt:100
```

```ts
{ "filter.id": ["$gt:10", "$lt:100"] }
```

Runtime validation enforces: field allowlist (`filterable`), operator allowlist per field (`ops`), and value type compatibility.

## Filter groups

Groups let you build nested AND/OR boolean logic.

### Assigning conditions to a group: `$g:<id>`

Prefix any filter DSL with `$g:<groupId>:`:

```txt
filter.status=$g:1:$eq:active
```

Within a group, the **first** condition cannot have `$and`/`$or`. Following conditions may be prefixed with `$and` or `$or`.

### Group tree definitions: `group.<id>.*`

Define parent-child relationships between groups:

- `group.<id>.parent` — parent group id (integer string)
- `group.<id>.join` — how this group joins its parent (`$and` or `$or`)
- `group.<id>.op` — default join for this group's children (optional)

Rules: root group id is always `"0"`. `group.0.parent` and `group.0.join` are forbidden. Cycles are rejected. Child groups are resolved in numeric order.

**Example:** `(status == active OR status == postponed) AND (id > 10)`

```ts
const parsed = queryParamsSchema().parse({
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

## Discriminated unions

Both `select()` and `paginate()` accept `z.discriminatedUnion()` (or `z.union()` of objects) as `dataSchema`. The `selectable` paths are typed as the union of all member paths.

```ts
const Codec1 = z.object({ id: z.number(), name: z.string() });
const Codec2 = z.object({ id: z.number(), title: z.string() });
const UnionSchema = z.discriminatedUnion("type", [
  Codec1.extend({ type: z.literal("codec1") }),
  Codec2.extend({ type: z.literal("codec2") }),
]);
const VideoSchema = z.object({ type: z.literal("video"), id: z.number(), duration: z.number(), codec: UnionSchema });
const AudioSchema = z.object({ type: z.literal("audio"), id: z.number(), bitrate: z.number() });
const MediaSchema = z.discriminatedUnion("type", [VideoSchema, AudioSchema]);
```

### Compile-time enforcement on `selectable`

The discriminator field **must** be present in `selectable`. Omitting it is a TypeScript error:

```ts
// ✗ Compile error — "type" is missing from selectable
select({
  dataSchema: MediaSchema,
  selectable: ["id", "name"],       // ← TypeScript error
  defaultSelect: "*",
});

// ✓ OK — "type" is included
select({
  dataSchema: MediaSchema,
  selectable: ["id", "name", "type"],
  defaultSelect: "*",
});
```

The same applies to `paginate()`:

```ts
// ✗ Compile error
paginate({
  paginationType: "LIMIT_OFFSET",
  dataSchema: MediaSchema,
  selectable: ["id", "duration"],   // ← missing "type"
  defaultSelect: "*",
  defaultLimit: 20,
  maxLimit: 100,
});

// ✓ OK
paginate({
  paginationType: "LIMIT_OFFSET",
  dataSchema: MediaSchema,
  selectable: ["id", "type", "duration"],
  defaultSelect: ["id", "type"],
  defaultLimit: 20,
  maxLimit: 100,
});
```

### Runtime rejection of explicit `select` without discriminator

Even though the type system ensures the discriminator is in `selectable`, a client could still send a `select` query that omits it. This is rejected at runtime:

```ts
const { queryParamsSchema } = select({
  dataSchema: MediaSchema,
  selectable: ["id", "type", "duration", "bitrate"],
  defaultSelect: ["id", "type"],
});

// ✗ Missing "type" → validation error
queryParamsSchema().safeParse({ select: "id,duration" });
// → 'select must include the discriminator field "type" when using a discriminated union'

// ✓ select=* always works — expands to all selectable fields including the discriminator
queryParamsSchema().parse({ select: "*" });
// → ["id", "type", "duration", "bitrate"]

// ✓ Including the discriminator explicitly
queryParamsSchema().parse({ select: "id,type,duration" });
// → ["id", "type", "duration"]
```

### Union-preserving response validation

When using a discriminated union, `validatorSchema` and `responseSchema` preserve the union structure — each option is projected independently. A response item only needs to match **one** of the union options:

```ts
const { queryParamsSchema, validatorSchema } = select({
  dataSchema: MediaSchema,
  selectable: ["id", "type", "duration", "bitrate"],
  defaultSelect: "*",
});

const parsed = queryParamsSchema().parse({ select: "id,type,duration,bitrate" });
const schema = validatorSchema(parsed.select);

// ✓ Video item — matches VideoSchema option
schema.parse({ data: [{ id: 1, type: "video", duration: 120 }] });

// ✓ Audio item — matches AudioSchema option
schema.parse({ data: [{ id: 2, type: "audio", bitrate: 320 }] });

// ✓ Mixed array — each item matches its own option
schema.parse({
  data: [
    { id: 1, type: "video", duration: 120 },
    { id: 2, type: "audio", bitrate: 320 },
  ],
});

// ✗ Invalid — type "video" with bitrate instead of duration
schema.safeParse({ data: [{ id: 1, type: "video", bitrate: 320 }] });
// → fails validation
```

## Extending `queryParamsSchema`

Both `select()` and `paginate()` support extending `queryParamsSchema` with additional fields:

```ts
// paginate()
const parsed = queryParamsSchema({
  search: z.string().optional(),
  locale: z.enum(["en", "fr"]).default("en"),
}).parse({ limit: "10", search: "alice", locale: "fr" });
// parsed.pagination → { type: "LIMIT_OFFSET", limit: 10, … }
// parsed.search     → "alice"
// parsed.locale     → "fr"

// select()
const parsed = queryParamsSchema({ search: z.string().optional() }).parse({
  select: "id,name",
  search: "widget",
});
// parsed.select.fields → ["id", "name"]
// parsed.search → "widget"
```

Extra fields are validated together — errors from both sides are collected in a single `ZodError`.

## End-to-end examples

### LIMIT/OFFSET

```txt
?limit=20&page=1&select=id,status,createdAt&sortBy=createdAt:DESC&filter.status=$ilike:act&filter.id=$gt:10
```

```ts
const parsed = queryParamsSchema().parse({
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
//   filters: { type: "and", items: [...] }
// }
```

### CURSOR with coercion

```ts
const { queryParamsSchema } = paginate({
  paginationType: "CURSOR",
  dataSchema: ModelSchema,
  cursorProperty: "id", // z.number() → cursor is coerced to number
  selectable: ["id", "status", "createdAt"],
  defaultSelect: ["id", "createdAt"],
});

const parsed = queryParamsSchema().parse({ cursor: "123", limit: "10" });
// parsed.pagination.cursor → 123 (coerced from "123")
```

### Validating a response

```ts
const { responseSchema } = paginate({
  paginationType: "LIMIT_OFFSET",
  dataSchema: ModelSchema,
  selectable: ["id", "status", "createdAt", "meta.score"],
  defaultSelect: '*',
  defaultLimit: 20,
  maxLimit: 100,
});

responseSchema.parse({
  data: [{ id: 1, status: "active", createdAt: new Date(), meta: { score: 42 } }],
  pagination: { itemsPerPage: 20, totalItems: 1, currentPage: 1, totalPages: 1 },
});

type Response = z.infer<typeof responseSchema>;
// Response["data"][0] → { id?: number; status?: string; createdAt?: Date; meta?: { score: number } }
// Response["pagination"].totalItems → number  ✓
```

## TypeScript reference

<details>
<summary><code>paginate()</code> overloads</summary>

```ts
// Overload 1 — LIMIT_OFFSET
export function paginate<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedPath<TSchema>[],
>(
  config: CommonQueryConfigFromSchema<TSchema, TSelectable[number]> & { paginationType: "LIMIT_OFFSET" },
): PaginateResult<TSchema, TSelectable[number], "LIMIT_OFFSET">;

// Overload 2 — CURSOR
export function paginate<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedPath<TSchema>[],
>(
  config: CommonQueryConfigFromSchema<TSchema, TSelectable[number]> & CursorPaginationConfig<…>,
): PaginateResult<TSchema, TSelectable[number], "CURSOR">;
```

</details>

<details>
<summary><code>select()</code> overloads</summary>

```ts
// Overload 1 — responseType: 'one'
export function select<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedPath<TSchema>[],
>(
  config: SelectConfig<TSchema, TSelectable[number], 'one'> & { responseType: 'one' },
): SelectResult<TSchema, TSelectable[number], 'one'>;

// Overload 2 — responseType: 'many' (default)
export function select<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedPath<TSchema>[],
>(
  config: SelectConfig<TSchema, TSelectable[number]> & { responseType?: 'many' },
): SelectResult<TSchema, TSelectable[number], 'many'>;
```

</details>

### Exported types

| Type | Description |
|---|---|
| `DataSchema` | `z.ZodObject \| z.ZodDiscriminatedUnion \| z.ZodUnion` |
| `AllowedPath<TSchema>` | All valid dot-notation paths for a given schema |
| `SelectConfig<TSchema, TSelectable>` | Configuration for `select()` |
| `SelectResult<TSchema, TSelectable, TResponseType?>` | Return type of `select()`. `TResponseType` narrows `validatorSchema` return and `responseType` property. |
| `SelectQueryParams<TSchema, TSelectable>` | Parsed output of `select()` — `{ select: SelectQueryPayload }` |
| `SelectQueryPayload<TSchema, TSelectable, TResponseType?>` | Inner select payload — `{ fields, responseType }`. Passed to `validatorSchema()`. |
| `SelectOneQueryPayload<TSchema, TSelectable?>` | Shorthand for `SelectQueryPayload<…, 'one'>` |
| `SelectManyQueryPayload<TSchema, TSelectable?>` | Shorthand for `SelectQueryPayload<…, 'many'>` |
| `SelectResponse<TSchema, TSelect, TResponseType?>` | Response type: `{ data: … }` — array when `'many'`, single object when `'one'` |
| `SelectOneResponse<TSchema, TSelect?>` | Shorthand for `SelectResponse<…, 'one'>` |
| `SelectManyResponse<TSchema, TSelect?>` | Shorthand for `SelectResponse<…, 'many'>` |
| `TypedProjectedData<TSchema, TSelect>` | Projected data item with real value types (used in response types) |
| `ProjectedData<TSchema, TSelect>` | Projected data item with `unknown` values (key autocompletion only) |
| `PaginateResult<TSchema, TSelectable?, TType?>` | Return type of `paginate()` |

## Adapters

`zod-paginate` is ORM/query-builder agnostic by design. **Adapters** bridge the gap between the parsed output and your data layer.

| Adapter | Description | Link |
|---|---|---|
| **zod-paginate-drizzle** | Drizzle ORM adapter — maps parsed pagination, filters, sorting, and select to Drizzle queries. | [GitHub](https://github.com/nolway/zod-paginate-drizzle) |
