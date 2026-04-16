import { z } from 'zod';
import {
  type AllowedPath,
  type AllowedSelectablePath,
  computeSelect,
  type DataSchema,
  type EnsureDiscriminatorInSelectable,
  expandSelect,
  findNestedDiscriminators,
  getDiscriminatorKey,
  getOwnProp,
  getZodAtPath,
  type InferData,
  isPlainObject,
  isZodSchema,
  type NoDuplicateProperties,
  type NoDuplicates,
  type Path,
  type PathValue,
  pickFromAllowlist,
  projectDataSchemaPreservingUnion,
  resolveToZodObject,
  SelectSchema,
  type TypedProjectedData,
  type UntypedSelectableConfig,
  type ZodShape,
} from './select';

/* ---------------------------------- */
/* Querystring value types */
/* ---------------------------------- */

type QueryStringValue = string | string[] | undefined;
type QueryStringRecord = Record<string, QueryStringValue>;

/* ---------------------------------- */
/* Pagination config */
/* ---------------------------------- */

interface LimitOffsetPaginationConfig {
  /** Pagination mode: classic limit/offset with page numbers. */
  paginationType: 'LIMIT_OFFSET';
}

interface CursorPaginationConfig<T> {
  /** Pagination mode: cursor-based (keyset). */
  paginationType: 'CURSOR';
  /** Field used as cursor. Its Zod type determines cursor coercion (number, string, or ISO date). */
  cursorProperty: Path<T>;
}

/* ---------------------------------- */
/* Common input normalizers */
/* ---------------------------------- */

/**
 * We often want to allow both single values and arrays in the querystring, e.g. "select=field1,field2" or "select[]=field1&select[]=field2".
 * This function normalizes both cases to a string array.
 */
function toStringArrayFromQueryString(v: QueryStringValue): string[] {
  if (v === undefined) return [];
  if (Array.isArray(v)) return v;
  return [v];
}

/**
 * Zod schema for a querystring parameter that can be either a single string or an array of strings.
 * It normalizes the output to always be an array of strings.
 */
const StringOrStringArraySchema = z
  .union([z.string(), z.array(z.string())])
  .transform((v) => (typeof v === 'string' ? [v] : v));

/* ---------------------------------- */
/* Sort */
/* ---------------------------------- */

export const SortDirectionSchema = z.enum(['ASC', 'DESC']).meta({
  description: 'Sort direction',
});
export type SortDirection = z.infer<typeof SortDirectionSchema>;

export const SortItemSchema = z
  .object({
    property: z.string().min(1).meta({ description: 'Field name to sort by' }),
    direction: SortDirectionSchema,
  })
  .meta({ description: 'A single sort instruction (field + direction)' });
export type SortItem = z.infer<typeof SortItemSchema>;

/**
 * Parse "field:ASC" into a SortItem.
 * The input must have a colon separating the field and direction, and the direction must be either "ASC" or "DESC" (case-insensitive).
 * */
function parseSortItem(raw: string): SortItem {
  const [propertyRaw, dirRaw] = raw.split(':');
  const property = (propertyRaw ?? '').trim();
  const direction = SortDirectionSchema.parse((dirRaw ?? '').trim());
  return SortItemSchema.parse({ property, direction });
}

/* ---------------------------------- */
/* Conditions + grouping */
/* ---------------------------------- */

/**
 * Supported operators.
 * $eq: equality (for strings, numbers, dates)
 * $null: checks for null (ignores the value)
 * $in: checks if the field value is in the provided array (for strings, numbers, dates)
 * $gt, $gte, $lt, $lte: comparison operators (for numbers and dates)
 * $btw: checks if the field value is between two values (for numbers and dates)
 * $ilike: case-insensitive substring match (for strings)
 * $sw: case-insensitive starts-with match (for strings)
 * $contains: checks if the field value contains the provided value (for strings)
 */
export const OperatorSchema = z.enum([
  '$eq',
  '$null',
  '$in',
  '$gt',
  '$gte',
  '$lt',
  '$lte',
  '$btw',
  '$ilike',
  '$sw',
  '$contains',
]);
export type Operator = z.infer<typeof OperatorSchema>;

/**
 * Logical combinators for grouping conditions. $and and $or can be used to combine multiple conditions within the same group.
 */
export const CombinatorSchema = z.enum(['$and', '$or']);
export type Combinator = z.infer<typeof CombinatorSchema>;

const ROOT_GROUP_ID = '0';
export const IntegerStringSchema = z.string().regex(/^\d+$/, 'Must be an integer string');

/**
 * Regex for validating ISO date strings (YYYY-MM-DD).
 */
export const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Regex for validating ISO datetime strings (YYYY-MM-DDTHH:mm:ss.sssZ or with timezone offset).
 */
export const ISO_DATETIME_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})$/;

export const NumericStringSchema = z
  .string()
  .trim()
  .regex(/^\d+$/, 'Must be a numeric string')
  .transform((s) => Number(s));

export const NumOrDateSchema = z.union([z.number(), z.string()]);

type FieldType = 'string' | 'number' | 'date' | 'any';

type FieldTypeFromValue<V> = V extends Date
  ? 'date'
  : V extends number
    ? 'number'
    : V extends string
      ? 'string'
      : 'any';

type CommonOps = '$eq' | '$null' | '$in' | '$contains';
type StringOnlyOps = '$ilike' | '$sw';
type ComparableOps = '$gt' | '$gte' | '$lt' | '$lte' | '$btw';

type OpsForFieldType<TKind extends FieldType> = TKind extends 'string'
  ? CommonOps | StringOnlyOps
  : TKind extends 'number'
    ? CommonOps | ComparableOps
    : TKind extends 'date'
      ? CommonOps | ComparableOps
      : Operator;

export const ConditionSchema = z
  .discriminatedUnion('op', [
    z.object({
      group: IntegerStringSchema,
      combinator: CombinatorSchema.optional(),
      op: z.literal('$null'),
      not: z.literal(true).optional(),
    }),

    z.object({
      group: IntegerStringSchema,
      combinator: CombinatorSchema.optional(),
      op: z.literal('$eq'),
      not: z.literal(true).optional(),
      value: NumOrDateSchema,
    }),

    z.object({
      group: IntegerStringSchema,
      combinator: CombinatorSchema.optional(),
      op: z.enum(['$ilike', '$sw']),
      not: z.literal(true).optional(),
      value: z.string(),
    }),

    z.object({
      group: IntegerStringSchema,
      combinator: CombinatorSchema.optional(),
      op: z.enum(['$in', '$contains']),
      not: z.literal(true).optional(),
      value: z.array(z.string()),
    }),

    z.object({
      group: IntegerStringSchema,
      combinator: CombinatorSchema.optional(),
      op: z.enum(['$gt', '$gte', '$lt', '$lte']),
      not: z.literal(true).optional(),
      value: NumOrDateSchema,
    }),

    z.object({
      group: IntegerStringSchema,
      combinator: CombinatorSchema.optional(),
      op: z.literal('$btw'),
      not: z.literal(true).optional(),
      value: z.tuple([NumOrDateSchema, NumOrDateSchema]),
    }),
  ])
  .meta({
    id: 'FilterCondition',
    description: 'A single filter condition with operator, optional negation, and value',
  });

export type Condition = z.infer<typeof ConditionSchema>;

/* ---------------------------------- */
/* Filters AST */
/* ---------------------------------- */

export interface WhereFilter {
  type: 'filter';
  field: string;
  condition: Condition;
}
export interface WhereAnd {
  type: 'and';
  items: WhereNode[];
}
export interface WhereOr {
  type: 'or';
  items: WhereNode[];
}
export type WhereNode = WhereFilter | WhereAnd | WhereOr;

function and(items: WhereNode[]): WhereNode {
  if (items.length === 1 && items[0]) return items[0];
  return { type: 'and', items };
}

function or(items: WhereNode[]): WhereNode {
  if (items.length === 1 && items[0]) return items[0];
  return { type: 'or', items };
}

function fold(op: Combinator | undefined, left: WhereNode, right: WhereNode): WhereNode {
  if (op === '$or') {
    if (left.type === 'or') return or([...left.items, right]);
    return or([left, right]);
  }
  if (left.type === 'and') return and([...left.items, right]);
  return and([left, right]);
}

const WhereNodeSchema: z.ZodType<WhereNode> = z
  .lazy(() =>
    z.union([
      z.object({ type: z.literal('filter'), field: z.string(), condition: ConditionSchema }),
      z.object({ type: z.literal('and'), items: z.array(WhereNodeSchema) }),
      z.object({ type: z.literal('or'), items: z.array(WhereNodeSchema) }),
    ]),
  )
  .meta({
    id: 'WhereNode',
    description:
      'Recursive filter AST node: a single filter condition, or an AND/OR group of nodes',
  });

/* ---------------------------------- */
/* Group tree */
/* ---------------------------------- */

interface GroupDef {
  parent?: string;
  join?: Combinator;
  op?: Combinator;
}
type GroupDefs = Record<string, GroupDef>;

function extractGroupDefs(q: Record<string, unknown>): GroupDefs {
  const defs: GroupDefs = {};

  for (const [k, v] of Object.entries(q)) {
    if (!k.startsWith('group.')) continue;

    const rest = k.slice('group.'.length);
    const dotIdx = rest.indexOf('.');
    if (dotIdx === -1) continue;

    const groupIdRaw = rest.slice(0, dotIdx).trim();
    const prop = rest.slice(dotIdx + 1).trim();

    const parsedId = IntegerStringSchema.safeParse(groupIdRaw);
    if (!parsedId.success) continue;
    const id = parsedId.data;

    const first = Array.isArray(v) ? v[0] : v;
    const valueStr = typeof first === 'string' ? first : '';

    const current = defs[id] ?? {};

    if (prop === 'parent') {
      defs[id] = { ...current, parent: IntegerStringSchema.parse(valueStr.trim()) };
      continue;
    }
    if (prop === 'join') {
      defs[id] = { ...current, join: CombinatorSchema.parse(valueStr.trim()) };
      continue;
    }
    if (prop === 'op') {
      defs[id] = { ...current, op: CombinatorSchema.parse(valueStr.trim()) };
      continue;
    }
  }

  return defs;
}

function validateGroupDefs(defs: GroupDefs): void {
  const root = defs[ROOT_GROUP_ID];
  if (root && (root.parent !== undefined || root.join !== undefined)) {
    throw new Error(
      `group.0 can only define "op". "parent" and "join" are not allowed on root group "0".`,
    );
  }

  for (const [id, def] of Object.entries(defs)) {
    if (id === ROOT_GROUP_ID) continue;
    if (def.parent !== undefined) IntegerStringSchema.parse(def.parent);
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();

  const visit = (id: string): void => {
    if (visited.has(id)) return;
    if (visiting.has(id)) throw new Error(`Group cycle detected at group "${id}".`);
    visiting.add(id);

    const parent = defs[id]?.parent;
    if (parent && parent !== ROOT_GROUP_ID) visit(parent);

    visiting.delete(id);
    visited.add(id);
  };

  for (const id of Object.keys(defs)) {
    if (id === ROOT_GROUP_ID) continue;
    visit(id);
  }
}

function buildGroupConditionExprs(rawFilters: Record<string, Condition[]>): Map<string, WhereNode> {
  const groupNodes = new Map<string, WhereFilter[]>();

  for (const [field, conditions] of Object.entries(rawFilters)) {
    for (const cond of conditions) {
      const groupId = cond.group;
      const list = groupNodes.get(groupId) ?? [];
      const isFirst = list.length === 0;

      if (isFirst && cond.combinator !== undefined) {
        throw new Error(
          `Invalid combinator "${cond.combinator}" on first condition of group "${groupId}". ` +
            `First condition in a group cannot define "$and" or "$or".`,
        );
      }

      list.push({ type: 'filter', field, condition: cond });
      groupNodes.set(groupId, list);
    }
  }

  const exprs = new Map<string, WhereNode>();
  for (const [groupId, nodes] of groupNodes.entries()) {
    if (nodes.length === 0) continue;
    if (!nodes[0]) continue;

    let current: WhereNode = nodes[0];
    for (let i = 1; i < nodes.length; i += 1) {
      const next = nodes[i];
      if (!next) break;
      current = fold(next.condition.combinator, current, next);
    }
    exprs.set(groupId, current);
  }

  return exprs;
}

function buildWhereAstWithGroups(
  rawFilters: Record<string, Condition[]>,
  groupDefs: GroupDefs,
): WhereNode {
  const groupExprs = buildGroupConditionExprs(rawFilters);

  const allGroupIds = new Set<string>();
  for (const id of groupExprs.keys()) allGroupIds.add(id);
  for (const id of Object.keys(groupDefs)) allGroupIds.add(id);
  allGroupIds.add(ROOT_GROUP_ID);

  const effectiveParent = (id: string): string => {
    if (id === ROOT_GROUP_ID) return ROOT_GROUP_ID;
    return groupDefs[id]?.parent ?? ROOT_GROUP_ID;
  };

  const childrenByParent = new Map<string, string[]>();
  for (const id of allGroupIds) {
    if (id === ROOT_GROUP_ID) continue;
    const parentId = effectiveParent(id);
    const arr = childrenByParent.get(parentId) ?? [];
    arr.push(id);
    childrenByParent.set(parentId, arr);
  }

  const sortNumericIds = (ids: string[]): string[] => {
    const pairs = ids.map((s) => ({ s, n: Number(s) }));
    pairs.sort((a, b) => a.n - b.n);
    return pairs.map((p) => p.s);
  };

  const visiting = new Set<string>();
  const resolved = new Map<string, WhereNode>();

  const resolveGroup = (id: string): WhereNode => {
    const cached = resolved.get(id);
    if (cached) return cached;

    if (visiting.has(id)) throw new Error(`Group cycle detected while resolving group "${id}".`);
    visiting.add(id);

    const items: { expr: WhereNode; join?: Combinator }[] = [];

    const own = groupExprs.get(id);
    if (own) items.push({ expr: own });

    const children = sortNumericIds(childrenByParent.get(id) ?? []);
    const parentOp = groupDefs[id]?.op;

    for (const childId of children) {
      const childExpr = resolveGroup(childId);
      const childJoin = groupDefs[childId]?.join;
      items.push({ expr: childExpr, join: childJoin ?? parentOp });
    }

    if (items.length === 0 || !items[0]) {
      const empty: WhereNode = { type: 'and', items: [] };
      resolved.set(id, empty);
      visiting.delete(id);
      return empty;
    }

    if (items[0].join !== undefined) {
      throw new Error(
        `Invalid group join "${items[0].join}" for the first item inside group "${id}". ` +
          `A group cannot start with "$and" or "$or" because there is nothing to join with.`,
      );
    }

    let current = items[0].expr;
    for (let i = 1; i < items.length; i += 1) {
      const next = items[i];
      if (!next) break;
      current = fold(next.join, current, next.expr);
    }

    resolved.set(id, current);
    visiting.delete(id);
    return current;
  };

  validateGroupDefs(groupDefs);
  return resolveGroup(ROOT_GROUP_ID);
}

/* ---------------------------------- */
/* DSL parsing */
/* ---------------------------------- */

/** Parse a string as either a finite number or an ISO date string. */
function parseNumOrDateStrict(raw: string, ctx: string): number | string {
  const s = raw.trim();

  if (/^[+-]?\d+(\.\d+)?$/.test(s)) {
    const n = Number(s);
    if (!Number.isFinite(n)) throw new Error(`Invalid number for ${ctx}: "${raw}"`);
    return n;
  }

  if (ISO_DATE_RE.test(s) || ISO_DATETIME_RE.test(s)) {
    const t = Date.parse(s);
    if (Number.isNaN(t)) throw new Error(`Invalid ISO date for ${ctx}: "${raw}"`);
    return s;
  }

  throw new Error(`Expected number or ISO date for ${ctx}, got "${raw}"`);
}

/** Ensure $btw bounds are both numbers or both dates. */
function assertSameKind(a: number | string, b: number | string, ctx: string): void {
  const ka = typeof a === 'number' ? 'number' : 'date';
  const kb = typeof b === 'number' ? 'number' : 'date';
  if (ka !== kb) {
    throw new Error(`$btw bounds must be same type (both number or both date) for ${ctx}`);
  }
}

/** Parse a single "filter.<field>" DSL string into a Condition. */
function parseSingleCondition(raw: string): Condition {
  const parts = raw.split(':');

  let group = ROOT_GROUP_ID;
  let cursor = parts;

  if (cursor[0] === '$g') {
    group = IntegerStringSchema.parse((cursor[1] ?? '').trim());
    cursor = cursor.slice(2);
    if (cursor.length === 0) {
      throw new Error(`Invalid group prefix in "${raw}" (missing condition after "$g:<id>")`);
    }
  }

  let combinator: Combinator | undefined;
  if (cursor[0] === '$and' || cursor[0] === '$or') {
    combinator = CombinatorSchema.parse(cursor[0]);
    cursor = cursor.slice(1);
    if (cursor.length === 0) {
      throw new Error(`Invalid combinator in "${raw}" (missing condition after "${combinator}")`);
    }
  }

  const hasNot = cursor[0] === '$not';
  if (hasNot && !cursor[1]) {
    throw new Error(`Invalid "$not" usage in "${raw}" (missing operator after "$not")`);
  }

  const head = hasNot ? cursor[1] : cursor[0];
  const rest = hasNot ? cursor.slice(2).join(':') : cursor.slice(1).join(':');
  const not = hasNot ? true : undefined;

  if (!head?.startsWith('$')) {
    return ConditionSchema.parse({
      group,
      combinator,
      op: '$eq',
      value: cursor.join(':'),
    });
  }

  const op = OperatorSchema.parse(head);

  if (op === '$null') return ConditionSchema.parse({ group, combinator, op: '$null', not });

  if (op === '$eq') {
    let value: number | string;
    try {
      value = parseNumOrDateStrict(rest, '$eq');
    } catch {
      value = rest;
    }
    return ConditionSchema.parse({ group, combinator, op: '$eq', not, value });
  }

  if (op === '$btw') {
    const [aRaw, bRaw] = rest.split(',');
    if (!aRaw || !bRaw) throw new Error(`Invalid $btw "${raw}" (expected "$btw:a,b")`);
    const a = parseNumOrDateStrict(aRaw, '$btw');
    const b = parseNumOrDateStrict(bRaw, '$btw');
    assertSameKind(a, b, '$btw');
    return ConditionSchema.parse({ group, combinator, op: '$btw', not, value: [a, b] });
  }

  if (op === '$in' || op === '$contains') {
    const arr = rest
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    return ConditionSchema.parse({ group, combinator, op, not, value: arr });
  }

  if (op === '$gt' || op === '$gte' || op === '$lt' || op === '$lte') {
    const v = parseNumOrDateStrict(rest, op);
    return ConditionSchema.parse({ group, combinator, op, not, value: v });
  }

  // $ilike | $sw
  return ConditionSchema.parse({ group, combinator, op, not, value: rest });
}

/* ---------------------------------- */
/* Extract raw filters */
/* ---------------------------------- */

function extractAndNormalizeRawFilters(q: QueryStringRecord): Record<string, Condition[]> {
  const result: Record<string, Condition[]> = {};

  for (const [k, v] of Object.entries(q)) {
    if (!k.startsWith('filter.')) continue;

    const field = k.slice('filter.'.length).trim();
    if (!field) continue;

    const rawList = toStringArrayFromQueryString(v);
    result[field] = rawList.filter(Boolean).map(parseSingleCondition);
  }

  return result;
}

function toQueryStringRecord(q: Record<string, unknown>): QueryStringRecord {
  const out: QueryStringRecord = {};
  for (const [k, v] of Object.entries(q)) {
    if (typeof v === 'string') {
      out[k] = v;
      continue;
    }
    if (Array.isArray(v) && v.every((x) => typeof x === 'string')) {
      out[k] = v;
      continue;
    }
    out[k] = undefined;
  }
  return out;
}

interface FilterableFieldConfig<TKind extends FieldType> {
  type: TKind;
  ops: readonly OpsForFieldType<TKind>[];
}

/** Configuration shared by all pagination modes. */
export interface CommonQueryConfigFromSchema<
  TSchema extends DataSchema,
  TSelectable extends AllowedSelectablePath<TSchema> = AllowedSelectablePath<TSchema>,
> {
  /** Zod schema representing one data item (object, discriminated union, or union). */
  dataSchema: TSchema;

  /** Allowlist of selectable fields (dot-notation paths). Enables the `select` query parameter. */
  selectable: readonly TSelectable[];
  /** Allowlist of sortable fields. Enables the `sortBy` query parameter. Unknown sort fields are rejected. */
  sortable?: readonly AllowedPath<TSchema>[];

  /** Map of filterable fields to their allowed type and operators. Enables the `filter.*` query parameters. */
  filterable?: Partial<{
    [P in AllowedPath<TSchema>]: FilterableFieldConfig<
      FieldTypeFromValue<PathValue<InferData<TSchema>, P>>
    >;
  }>;

  /** Default sort order applied when `sortBy` is omitted from the query. */
  defaultSortBy?: readonly { property: AllowedPath<TSchema>; direction: SortDirection }[];
  /** Default number of items per page when `limit` is omitted. */
  defaultLimit: number;

  /** Default fields returned when `select` is omitted. Use `"*"` to select all. */
  defaultSelect: readonly TSelectable[] | '*';
  /** Maximum allowed value for `limit`. Requests exceeding this are rejected. */
  maxLimit: number;
}

/**
 * Full query config type, which includes pagination-specific properties depending on the pagination type.
 */
export type QueryConfigFromSchema<
  TSchema extends DataSchema,
  TSelectable extends AllowedSelectablePath<TSchema> = AllowedSelectablePath<TSchema>,
> = CommonQueryConfigFromSchema<TSchema, TSelectable> &
  (LimitOffsetPaginationConfig | CursorPaginationConfig<InferData<TSchema>>);

/* ---------------------------------- */
/* Runtime filterable map */
/* ---------------------------------- */

interface FilterableRuntimeFieldConfig {
  type: FieldType;
  ops: readonly Operator[];
}

function toFilterableRuntime(
  filterable: Partial<Record<string, { type: FieldType; ops: readonly Operator[] }>> | undefined,
): Record<string, FilterableRuntimeFieldConfig> {
  const out: Record<string, FilterableRuntimeFieldConfig> = {};
  if (!filterable) return out;

  for (const [k, v] of Object.entries(filterable)) {
    if (!v) continue;
    out[k] = { type: v.type, ops: [...v.ops] };
  }

  return out;
}

function computeLimit(limit: number | undefined, defaultLimit: number): number {
  if (typeof limit === 'number') return limit;
  return defaultLimit;
}

/* ---------------------------------- */
/* Runtime value/type validation */
/* ---------------------------------- */

function isISODateString(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  if (!(ISO_DATE_RE.test(v) || ISO_DATETIME_RE.test(v))) return false;
  return !Number.isNaN(Date.parse(v));
}

function isFiniteNumber(v: unknown): boolean {
  return typeof v === 'number' && Number.isFinite(v);
}

function validateConditionType(expected: FieldType, cond: Condition, field: string): string | null {
  if (expected === 'any') return null;

  switch (cond.op) {
    case '$null':
      return null;

    case '$eq':
      if (expected === 'number' && !isFiniteNumber(cond.value))
        return `Field "${field}" expects a number for "$eq"`;
      if (expected === 'date' && !isISODateString(cond.value))
        return `Field "${field}" expects an ISO date for "$eq"`;
      if (expected === 'string' && typeof cond.value !== 'string')
        return `Field "${field}" expects a string for "$eq"`;
      return null;

    case '$ilike':
    case '$sw':
      if (expected !== 'string')
        return `Field "${field}" does not support "${cond.op}" (configured as ${expected})`;
      return null;

    case '$in':
    case '$contains':
      return null;

    case '$gt':
    case '$gte':
    case '$lt':
    case '$lte':
      if (expected === 'string')
        return `Field "${field}" does not support "${cond.op}" (configured as string)`;
      if (expected === 'number' && !isFiniteNumber(cond.value))
        return `Field "${field}" expects number for "${cond.op}"`;
      if (expected === 'date' && !isISODateString(cond.value))
        return `Field "${field}" expects ISO date for "${cond.op}"`;
      return null;

    case '$btw': {
      const [a, b] = cond.value;
      if (expected === 'string')
        return `Field "${field}" does not support "$btw" (configured as string)`;
      if (expected === 'number' && (!isFiniteNumber(a) || !isFiniteNumber(b)))
        return `Field "${field}" expects numbers for "$btw"`;
      if (expected === 'date' && (!isISODateString(a) || !isISODateString(b)))
        return `Field "${field}" expects ISO dates for "$btw"`;
      return null;
    }
  }
}

/* ---------------------------------- */
/* Sort defaults */
/* ---------------------------------- */

export interface SortItemTyped<TSchema extends DataSchema> {
  property: AllowedPath<TSchema>;
  direction: SortDirection;
}

function computeSortBy<TSchema extends DataSchema>(
  sortByRaw: string[] | undefined,
  config: Pick<CommonQueryConfigFromSchema<TSchema>, 'sortable' | 'defaultSortBy'>,
): SortItemTyped<TSchema>[] | undefined {
  if (sortByRaw) {
    const cleaned = sortByRaw.map((s) => s.trim()).filter(Boolean);
    if (cleaned.length > 0) {
      const seen = new Set<string>();
      const out: SortItemTyped<TSchema>[] = [];
      for (const raw of cleaned) {
        const parsed = parseSortItem(raw);

        const picked = pickFromAllowlist(config.sortable, parsed.property);
        if (!picked) continue;
        if (seen.has(picked)) continue;
        seen.add(picked);

        out.push({ property: picked, direction: parsed.direction });
      }
      return out.length > 0 ? out : undefined;
    }
  }

  if (config.defaultSortBy && config.defaultSortBy.length > 0) {
    return config.defaultSortBy.map((x) => ({ property: x.property, direction: x.direction }));
  }

  return undefined;
}

/* ---------------------------------- */
/* QueryParams output (generic) */
/* ---------------------------------- */

export interface LimitOffsetPaginationPayload<TSchema extends DataSchema> {
  type: 'LIMIT_OFFSET';
  limit: number;
  page?: number;
  sortBy?: SortItemTyped<TSchema>[];
  select?: AllowedPath<TSchema>[];
  filters?: WhereNode;
}

/**
 * Cursor is always a string in the query input, BUT we coerce it at parse-time
 * to match the type of cursorProperty (number / string / ISO date string).
 */
export interface CursorPaginationPayload<TSchema extends DataSchema> {
  type: 'CURSOR';
  limit: number;
  cursor?: number | string;
  cursorProperty: AllowedPath<TSchema>;
  sortBy?: SortItemTyped<TSchema>[];
  select?: AllowedPath<TSchema>[];
  filters?: WhereNode;
}

export type PaginationType = 'LIMIT_OFFSET' | 'CURSOR';

export type PaginationPayload<
  TSchema extends DataSchema,
  TType extends PaginationType = PaginationType,
> = TType extends 'LIMIT_OFFSET'
  ? LimitOffsetPaginationPayload<TSchema>
  : TType extends 'CURSOR'
    ? CursorPaginationPayload<TSchema>
    : never;

export interface PaginationQueryParams<
  TSchema extends DataSchema,
  TType extends PaginationType = PaginationType,
> {
  pagination: PaginationPayload<TSchema, TType>;
}

/* ---------------------------------- */
/* Validator response types            */
/* ---------------------------------- */

export interface LimitOffsetPaginationResponseMeta {
  itemsPerPage: number;
  totalItems: number;
  currentPage: number;
  totalPages: number;
  sortBy?: { property: string; direction: SortDirection }[];
  filter?: WhereNode;
}

export interface CursorPaginationResponseMeta {
  itemsPerPage: number;
  cursor: number | string | Date;
  sortBy?: { property: string; direction: SortDirection }[];
  filter?: WhereNode;
}

export interface LimitOffsetPaginationResponse<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
> {
  data: TypedProjectedData<TSchema, TSelect>[];
  pagination: LimitOffsetPaginationResponseMeta;
}

export interface CursorPaginationResponse<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
> {
  data: TypedProjectedData<TSchema, TSelect>[];
  pagination: CursorPaginationResponseMeta;
}

export type PaginationResponse<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
  TType extends PaginationType = PaginationType,
> = TType extends 'LIMIT_OFFSET'
  ? LimitOffsetPaginationResponse<TSchema, TSelect>
  : TType extends 'CURSOR'
    ? CursorPaginationResponse<TSchema, TSelect>
    : never;

/* ---------------------------------- */
/* Response schema shapes (ZodObject)  */
/* ---------------------------------- */

/**
 * Re-exported from select.ts for use in paginate response schema shapes.
 */
// ZodShape is imported from './select' and used locally only.

interface LimitOffsetPaginationMetaSchemaShapeDef {
  itemsPerPage: z.ZodNumber;
  totalItems: z.ZodNumber;
  currentPage: z.ZodNumber;
  totalPages: z.ZodNumber;
  sortBy: z.ZodOptional<z.ZodArray<z.ZodObject<z.ZodRawShape>>>;
  filter: z.ZodOptional<z.ZodType<WhereNode>>;
}
export type LimitOffsetPaginationMetaSchemaShape =
  ZodShape<LimitOffsetPaginationMetaSchemaShapeDef>;

interface CursorPaginationMetaSchemaShapeDef {
  itemsPerPage: z.ZodNumber;
  cursor: z.ZodType<number | string | Date>;
  sortBy: z.ZodOptional<z.ZodArray<z.ZodObject<z.ZodRawShape>>>;
  filter: z.ZodOptional<z.ZodType<WhereNode>>;
}
export type CursorPaginationMetaSchemaShape = ZodShape<CursorPaginationMetaSchemaShapeDef>;

interface LimitOffsetResponseSchemaShapeDef {
  data: z.ZodArray<z.ZodType>;
  pagination: z.ZodObject<LimitOffsetPaginationMetaSchemaShape>;
}
export type LimitOffsetResponseSchemaShape = ZodShape<LimitOffsetResponseSchemaShapeDef>;

interface CursorResponseSchemaShapeDef {
  data: z.ZodArray<z.ZodType>;
  pagination: z.ZodObject<CursorPaginationMetaSchemaShape>;
}
export type CursorResponseSchemaShape = ZodShape<CursorResponseSchemaShapeDef>;

export type PaginationResponseSchemaShape<TType extends PaginationType> =
  TType extends 'LIMIT_OFFSET'
    ? LimitOffsetResponseSchemaShape
    : TType extends 'CURSOR'
      ? CursorResponseSchemaShape
      : LimitOffsetResponseSchemaShape | CursorResponseSchemaShape;

/**
 * Result type returned by `paginate()`. Use this instead of
 * `ReturnType<typeof paginate>` to preserve the generic `TSchema`.
 *
 * @example
 * function createPaginator(): PaginateResult<typeof MySchema> {
 *   return paginate({ dataSchema: MySchema, … });
 * }
 */
export interface PaginateResult<
  TSchema extends DataSchema,
  TType extends PaginationType = PaginationType,
> {
  queryParamsSchema: {
    (): z.ZodType<PaginationQueryParams<TSchema, TType>>;
    <TExtraShape extends z.ZodRawShape>(
      extraShape: TExtraShape,
    ): z.ZodType<PaginationQueryParams<TSchema, TType> & z.infer<z.ZodObject<TExtraShape>>>;
  };
  validatorSchema: (
    parsed?: PaginationPayload<TSchema>,
  ) => z.ZodType<PaginationResponse<TSchema, AllowedPath<TSchema>, TType>>;
  responseSchema: z.ZodObject<PaginationResponseSchemaShape<TType>>;
}

function callMethodIfReturnsZod(obj: unknown, methodName: string): z.ZodType | undefined {
  if (!isPlainObject(obj)) return undefined;

  const maybeFn = getOwnProp(obj, methodName);
  if (typeof maybeFn !== 'function') return undefined;

  const result = maybeFn.call(obj);
  if (isZodSchema(result)) return result;

  return undefined;
}

function getInnerSchemaFromDef(obj: unknown): z.ZodType | undefined {
  if (!isPlainObject(obj)) return undefined;

  const def = getOwnProp(obj, 'def') ?? getOwnProp(obj, '_def');
  if (!isPlainObject(def)) return undefined;

  const candidates = ['innerType', 'schema', 'type', 'in', 'out'];

  for (const key of candidates) {
    const v = getOwnProp(def, key);
    if (isZodSchema(v)) return v;
  }

  return undefined;
}

function unwrapSchema(schema: z.ZodType): z.ZodType {
  let current: unknown = schema;

  for (let i = 0; i < 30; i += 1) {
    const unwrapped = callMethodIfReturnsZod(current, 'unwrap');
    if (unwrapped) {
      current = unwrapped;
      continue;
    }

    const removedDefault = callMethodIfReturnsZod(current, 'removeDefault');
    if (removedDefault) {
      current = removedDefault;
      continue;
    }

    const innerType = callMethodIfReturnsZod(current, 'innerType');
    if (innerType) {
      current = innerType;
      continue;
    }

    const sourceType = callMethodIfReturnsZod(current, 'sourceType');
    if (sourceType) {
      current = sourceType;
      continue;
    }

    const innerFromDef = getInnerSchemaFromDef(current);
    if (innerFromDef) {
      current = innerFromDef;
      continue;
    }

    break;
  }

  if (isZodSchema(current)) return current;
  return schema;
}

/**
 * Robust constructor name getter that works with Zod objects (constructor is on the prototype).
 * No `as`, no unsafe casts.
 */
function getConstructorName(v: unknown): string | undefined {
  if (typeof v !== 'object' || v === null) return undefined;

  const proto: unknown = Object.getPrototypeOf(v);
  if (typeof proto !== 'object' || proto === null) return undefined;

  const ctorUnknown: unknown = Reflect.get(proto, 'constructor');
  if (!(ctorUnknown instanceof Function)) return undefined;

  return ctorUnknown.name;
}

/* ---------------------------------- */
/* Cursor: schema inference + coercion */
/* ---------------------------------- */

/**
 * Return the expected cursor schema for API responses:
 * - number field => cursor: number
 * - string field => cursor: string
 * - date field   => cursor: ISO string OR Date (optional support)
 */
function cursorSchemaFromProperty<TSchema extends DataSchema>(
  dataSchema: TSchema,
  cursorProperty: AllowedPath<TSchema>,
): z.ZodType<number | string | Date> {
  const raw = getZodAtPath(dataSchema, `${cursorProperty}`);
  const s = unwrapSchema(raw);
  const ctorName = getConstructorName(s);

  if (ctorName === 'ZodNumber') return z.number();
  if (ctorName === 'ZodString') return z.string();
  if (ctorName === 'ZodDate') return z.union([z.string().refine(isISODateString), z.date()]);

  // Unsupported cursor field type
  return z.never();
}

/**
 * Coerce the query input cursor (always string) into the right type based on cursorProperty.
 * - number field => "123" -> 123
 * - string field => "abc" -> "abc"
 * - date field   => "2022-01-01" -> "2022-01-01" (validated as ISO)
 */
function coerceCursorFromProperty<TSchema extends DataSchema>(
  dataSchema: TSchema,
  cursorProperty: AllowedPath<TSchema>,
  rawCursor: string,
): number | string {
  const schemaAtPath = unwrapSchema(getZodAtPath(dataSchema, `${cursorProperty}`));
  const ctorName = getConstructorName(schemaAtPath);

  if (ctorName === 'ZodNumber') {
    const s = rawCursor.trim();
    if (!/^[+-]?\d+$/.test(s)) throw new Error(`cursor must be an integer string`);
    const n = Number(s);
    if (!Number.isFinite(n)) throw new Error(`cursor must be a finite number`);
    return n;
  }

  if (ctorName === 'ZodString') {
    return rawCursor;
  }

  if (ctorName === 'ZodDate') {
    const s = rawCursor.trim();
    if (!isISODateString(s)) throw new Error(`cursor must be an ISO date string`);
    return s;
  }

  throw new Error(`cursorProperty "${cursorProperty}" must be a string|number|date`);
}

/* ---------------------------------- */
/* Response schema builders            */
/* ---------------------------------- */

interface LimitOffsetResponseSchemaParts {
  itemsPerPage: z.ZodNumber;
  totalItems: z.ZodNumber;
  currentPage: z.ZodNumber;
  totalPages: z.ZodNumber;
  sortBy: z.ZodOptional<z.ZodArray<z.ZodObject<z.ZodRawShape>>>;
  filter: z.ZodOptional<z.ZodType<WhereNode>>;
  metaDescription: string;
}

function buildLimitOffsetResponseSchema(
  dataItemSchema: z.ZodType,
  parts: LimitOffsetResponseSchemaParts,
): z.ZodObject<LimitOffsetResponseSchemaShape> {
  return z.object({
    data: z.array(dataItemSchema),
    pagination: z
      .object({
        itemsPerPage: parts.itemsPerPage,
        totalItems: parts.totalItems,
        currentPage: parts.currentPage,
        totalPages: parts.totalPages,
        sortBy: parts.sortBy,
        filter: parts.filter,
      })
      .meta({ description: parts.metaDescription }),
  });
}

interface CursorResponseSchemaParts {
  itemsPerPage: z.ZodNumber;
  cursor: z.ZodType<number | string | Date>;
  sortBy: z.ZodOptional<z.ZodArray<z.ZodObject<z.ZodRawShape>>>;
  filter: z.ZodOptional<z.ZodType<WhereNode>>;
  metaDescription: string;
  cursorValueDescription: string;
}

function buildCursorResponseSchema(
  dataItemSchema: z.ZodType,
  parts: CursorResponseSchemaParts,
): z.ZodObject<CursorResponseSchemaShape> {
  return z.object({
    data: z.array(dataItemSchema),
    pagination: z
      .object({
        itemsPerPage: parts.itemsPerPage,
        cursor: parts.cursor.meta({ description: parts.cursorValueDescription }),
        sortBy: parts.sortBy,
        filter: parts.filter,
      })
      .meta({ description: parts.metaDescription }),
  });
}

/* ---------------------------------- */
/* Factory */
/* ---------------------------------- */

/**
 * Generate Zod schemas and runtime validators for pagination query parameters, based on a config object.
 * @param config The configuration object defining the pagination behavior and allowed fields.
 * @returns An object containing:
 *   - `queryParamsSchema`: A Zod schema for validating and parsing the raw query parameters.
 *   - `validatorSchema`: A function that takes the already-parsed query parameters and returns a Zod schema for further validation (e.g. filters).
 *   - `responseSchema`: A pre-built Zod schema for validating the response (uses defaultSelect or all selectable fields).
 */
export function paginate<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedSelectablePath<TSchema>[],
  const TSortable extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
  const TDefaultSelect extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
  const TDefaultSortBy extends readonly {
    property: NoInfer<TSelectable[number]>;
    direction: SortDirection;
  }[] = readonly { property: NoInfer<TSelectable[number]>; direction: SortDirection }[],
>(
  config: Omit<
    CommonQueryConfigFromSchema<TSchema, TSelectable[number]>,
    'selectable' | 'defaultSelect' | 'sortable' | 'defaultSortBy' | 'filterable'
  > &
    LimitOffsetPaginationConfig & {
      /** Allowlist of selectable fields (dot-notation paths). Enables the `select` query parameter. */
      selectable: NoDuplicates<TSelectable> & EnsureDiscriminatorInSelectable<TSchema, TSelectable>;
      /** Default fields returned when `select` is omitted. Use `"*"` to select all. */
      defaultSelect: NoDuplicates<TDefaultSelect> | '*';
      /** Allowlist of sortable fields. Enables the `sortBy` query parameter. Unknown sort fields are rejected. */
      sortable?: NoDuplicates<TSortable>;
      /** Default sort order applied when `sortBy` is omitted from the query. */
      defaultSortBy?: NoDuplicateProperties<TDefaultSortBy>;
      /** Map of filterable fields to their allowed type and operators. Enables the `filter.*` query parameters. */
      filterable?: Partial<{
        [P in NoInfer<TSelectable[number]>]: FilterableFieldConfig<
          FieldTypeFromValue<PathValue<InferData<TSchema>, P>>
        >;
      }>;
    },
): PaginateResult<TSchema, 'LIMIT_OFFSET'>;

export function paginate<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedSelectablePath<TSchema>[],
  const TSortable extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
  const TDefaultSelect extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
  const TDefaultSortBy extends readonly {
    property: NoInfer<TSelectable[number]>;
    direction: SortDirection;
  }[] = readonly { property: NoInfer<TSelectable[number]>; direction: SortDirection }[],
>(
  config: Omit<
    CommonQueryConfigFromSchema<TSchema, TSelectable[number]>,
    'selectable' | 'defaultSelect' | 'sortable' | 'defaultSortBy' | 'filterable'
  > &
    CursorPaginationConfig<InferData<TSchema>> & {
      /** Allowlist of selectable fields (dot-notation paths). Enables the `select` query parameter. */
      selectable: NoDuplicates<TSelectable> & EnsureDiscriminatorInSelectable<TSchema, TSelectable>;
      /** Default fields returned when `select` is omitted. Use `"*"` to select all. */
      defaultSelect: NoDuplicates<TDefaultSelect> | '*';
      /** Allowlist of sortable fields. Enables the `sortBy` query parameter. Unknown sort fields are rejected. */
      sortable?: NoDuplicates<TSortable>;
      /** Default sort order applied when `sortBy` is omitted from the query. */
      defaultSortBy?: NoDuplicateProperties<TDefaultSortBy>;
      /** Map of filterable fields to their allowed type and operators. Enables the `filter.*` query parameters. */
      filterable?: Partial<{
        [P in NoInfer<TSelectable[number]>]: FilterableFieldConfig<
          FieldTypeFromValue<PathValue<InferData<TSchema>, P>>
        >;
      }>;
    },
): PaginateResult<TSchema, 'CURSOR'>;

export function paginate<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedSelectablePath<TSchema>[],
  const TSortable extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
  const TDefaultSelect extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
  const TDefaultSortBy extends readonly {
    property: NoInfer<TSelectable[number]>;
    direction: SortDirection;
  }[] = readonly { property: NoInfer<TSelectable[number]>; direction: SortDirection }[],
>(
  config: Omit<
    CommonQueryConfigFromSchema<TSchema, TSelectable[number]>,
    'selectable' | 'defaultSelect' | 'sortable' | 'defaultSortBy' | 'filterable'
  > & {
    /** Allowlist of selectable fields (dot-notation paths). Enables the `select` query parameter. */
    selectable: NoDuplicates<TSelectable> & EnsureDiscriminatorInSelectable<TSchema, TSelectable>;
    /** Default fields returned when `select` is omitted. Use `"*"` to select all. */
    defaultSelect: NoDuplicates<TDefaultSelect> | '*';
    /** Allowlist of sortable fields. Enables the `sortBy` query parameter. Unknown sort fields are rejected. */
    sortable?: NoDuplicates<TSortable>;
    /** Default sort order applied when `sortBy` is omitted from the query. */
    defaultSortBy?: NoDuplicateProperties<TDefaultSortBy>;
    /** Map of filterable fields to their allowed type and operators. Enables the `filter.*` query parameters. */
    filterable?: Partial<{
      [P in NoInfer<TSelectable[number]>]: FilterableFieldConfig<
        FieldTypeFromValue<PathValue<InferData<TSchema>, P>>
      >;
    }>;
  } & (LimitOffsetPaginationConfig | CursorPaginationConfig<InferData<TSchema>>),
): PaginateResult<TSchema>;

export function paginate<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedSelectablePath<TSchema>[],
  const TSortable extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
  const TDefaultSelect extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
  const TDefaultSortBy extends readonly {
    property: NoInfer<TSelectable[number]>;
    direction: SortDirection;
  }[] = readonly { property: NoInfer<TSelectable[number]>; direction: SortDirection }[],
>(
  config: Omit<
    CommonQueryConfigFromSchema<TSchema, TSelectable[number]>,
    'selectable' | 'defaultSelect' | 'sortable' | 'defaultSortBy' | 'filterable'
  > & {
    /** Allowlist of selectable fields (dot-notation paths). Enables the `select` query parameter. */
    selectable: NoDuplicates<TSelectable> & EnsureDiscriminatorInSelectable<TSchema, TSelectable>;
    /** Default fields returned when `select` is omitted. Use `"*"` to select all. */
    defaultSelect: NoDuplicates<TDefaultSelect> | '*';
    /** Allowlist of sortable fields. Enables the `sortBy` query parameter. Unknown sort fields are rejected. */
    sortable?: NoDuplicates<TSortable>;
    /** Default sort order applied when `sortBy` is omitted from the query. */
    defaultSortBy?: NoDuplicateProperties<TDefaultSortBy>;
    /** Map of filterable fields to their allowed type and operators. Enables the `filter.*` query parameters. */
    filterable?: Partial<{
      [P in TSelectable[number]]: FilterableFieldConfig<
        FieldTypeFromValue<PathValue<InferData<TSchema>, P>>
      >;
    }>;
  } & (LimitOffsetPaginationConfig | CursorPaginationConfig<InferData<TSchema>>),
): PaginateResult<TSchema> {
  const discriminatorKey = getDiscriminatorKey(config.dataSchema);
  const nestedDiscriminators = findNestedDiscriminators(config.dataSchema);

  const selectableStrings: string[] = [...config.selectable];

  const effectiveConfig: UntypedSelectableConfig = {
    selectable: selectableStrings,
    defaultSelect: config.defaultSelect === '*' ? '*' : Array.from(config.defaultSelect, String),
  };

  const allowedSelectable = new Set<string>(selectableStrings);

  const allowedSortable = new Set<string>();
  for (const f of config.sortable ?? []) allowedSortable.add(`${f}`);

  const filterable = toFilterableRuntime(config.filterable);
  const filterableOps = new Map(Object.entries(filterable).map(([k, v]) => [k, new Set(v.ops)]));

  const baseSchema = z.object({
    limit: NumericStringSchema.optional(),
    page: NumericStringSchema.optional(),

    /**
     * Query input is always a string if present.
     * We will coerce it later in the final transform (CURSOR mode only).
     */
    cursor: z.string().min(1).optional(),

    sortBy: StringOrStringArraySchema.optional(),
    select: SelectSchema.optional(),

    rawFilters: z.record(z.string(), z.array(ConditionSchema)),
    groupDefs: z.record(
      z.string(),
      z.object({
        parent: IntegerStringSchema.optional(),
        join: CombinatorSchema.optional(),
        op: CombinatorSchema.optional(),
      }),
    ),
  });

  /*
   * Build the root ZodObject with explicit named properties so that
   * OpenAPI tooling (zod-openapi, fastify-zod-openapi) can introspect
   * the query parameters. Dynamic keys (filter.*, group.*) pass through
   * via .catchall(z.unknown()). The actual validation/transforms happen
   * in the piped baseSchema below.
   */
  const rootShape: Record<string, z.ZodType> = {
    limit: z
      .string()
      .optional()
      .meta({
        description: `Maximum number of items to return per page (default: ${String(config.defaultLimit)}, max: ${String(config.maxLimit)})`,
        example: String(config.defaultLimit),
      }),
  };

  if (config.paginationType === 'LIMIT_OFFSET') {
    rootShape.page = z.string().optional().meta({
      description: 'Page number (1-based)',
      example: '1',
    });
  } else {
    rootShape.cursor = z.string().optional().meta({
      description: 'Cursor value for cursor-based pagination',
      example: '42',
    });
  }

  if (config.sortable && config.sortable.length > 0) {
    const defaultSortDesc =
      config.defaultSortBy && config.defaultSortBy.length > 0
        ? config.defaultSortBy.map((s) => `${s.property}:${s.direction}`).join(',')
        : 'none';
    rootShape.sortBy = z
      .union([z.string(), z.array(z.string())])
      .optional()
      .meta({
        description: `Sort by field and direction. Format: "field:ASC" or "field:DESC". Allowed fields: ${config.sortable.join(', ')}. Default: ${defaultSortDesc}`,
        example: config.sortable[0] ? `${config.sortable[0]}:ASC` : undefined,
      });
  }

  if (config.selectable.length > 0) {
    const defaultSelectDesc =
      config.defaultSelect === '*' ? '*' : [...config.defaultSelect].join(',');
    rootShape.select = z
      .string()
      .optional()
      .meta({
        description: `Comma-separated list of fields to return. Use "*" for all. Allowed fields: ${config.selectable.join(', ')}. Default: ${defaultSelectDesc}`,
        example: defaultSelectDesc,
      });
  }

  const baseQueryParamsSchema: z.ZodType<PaginationQueryParams<TSchema>> = z
    .object(rootShape)
    .catchall(z.unknown())
    .transform(
      (
        q,
      ): Record<string, unknown> & {
        rawFilters: Record<string, Condition[]>;
        groupDefs: GroupDefs;
      } => {
        const qs = toQueryStringRecord(q);

        return {
          ...q,
          rawFilters: extractAndNormalizeRawFilters(qs),
          groupDefs: extractGroupDefs(q),
        };
      },
    )
    .pipe(
      baseSchema
        .superRefine((val, ctx): void => {
          // Pagination mode constraints
          if (config.paginationType === 'LIMIT_OFFSET') {
            if (val.cursor !== undefined) {
              ctx.addIssue({
                code: 'custom',
                path: ['cursor'],
                message: `cursor is not allowed when paginationType is LIMIT_OFFSET`,
              });
            }
          }

          if (config.paginationType === 'CURSOR') {
            if (val.page !== undefined) {
              ctx.addIssue({
                code: 'custom',
                path: ['page'],
                message: `page is not allowed when paginationType is CURSOR`,
              });
            }

            if (`${config.cursorProperty}`.trim().length === 0) {
              ctx.addIssue({
                code: 'custom',
                path: [],
                message: `cursorProperty must be a non-empty string when paginationType is CURSOR`,
              });
            }

            // Validate that cursor (if provided) can be coerced for that cursorProperty
            if (val.cursor !== undefined) {
              try {
                void coerceCursorFromProperty(config.dataSchema, config.cursorProperty, val.cursor);
              } catch (e) {
                const message = e instanceof Error ? e.message : 'Invalid cursor';
                ctx.addIssue({
                  code: 'custom',
                  path: ['cursor'],
                  message,
                });
              }
            }
          }

          // limit / maxLimit
          if (typeof val.limit === 'number' && val.limit > config.maxLimit) {
            ctx.addIssue({
              code: 'custom',
              path: ['limit'],
              message: `limit must be <= ${config.maxLimit}`,
            });
          }

          // select allowlist + "*" expandability
          const selectForValidation: readonly string[] =
            val.select ??
            (effectiveConfig.defaultSelect === '*' ? ['*'] : effectiveConfig.defaultSelect);

          const hasWildcard = selectForValidation.includes('*');

          {
            let index = 0;

            for (const field of selectForValidation) {
              if (field === '*') {
                index += 1;
                continue;
              }

              if (allowedSelectable.size > 0 && !allowedSelectable.has(field)) {
                ctx.addIssue({
                  code: 'custom',
                  path: ['select', index],
                  message: `select field "${field}" is not allowed`,
                });
              }

              index += 1;
            }

            if (hasWildcard) {
              const expanded = expandSelect(selectForValidation, effectiveConfig);
              if (!expanded || expanded.length === 0) {
                ctx.addIssue({
                  code: 'custom',
                  path: ['select'],
                  message: `select "*" cannot be expanded (missing selectable in config)`,
                });
              }
            }

            if (
              discriminatorKey &&
              !hasWildcard &&
              !selectForValidation.includes(discriminatorKey)
            ) {
              ctx.addIssue({
                code: 'custom',
                path: ['select'],
                message: `select must include the discriminator field "${discriminatorKey}" when using a discriminated union`,
              });
            }

            // Check nested discriminated unions
            if (!hasWildcard) {
              for (const nested of nestedDiscriminators) {
                const hasAnyFieldUnderPrefix =
                  nested.prefix === ''
                    ? selectForValidation.length > 0
                    : selectForValidation.some(
                        (f) => f === nested.prefix || f.startsWith(`${nested.prefix}.`),
                      );
                if (
                  hasAnyFieldUnderPrefix &&
                  !selectForValidation.includes(nested.discriminatorPath)
                ) {
                  ctx.addIssue({
                    code: 'custom',
                    path: ['select'],
                    message: `select must include the discriminator field "${nested.discriminatorPath}" when selecting fields under "${nested.prefix}" (discriminated union)`,
                  });
                }
              }
            }
          }

          // sort allowlist
          if (val.sortBy) {
            if (!config.sortable || config.sortable.length === 0) {
              ctx.addIssue({
                code: 'custom',
                path: ['sortBy'],
                message: `sortBy is not allowed (no sortable fields configured)`,
              });
            } else {
              const cleaned = val.sortBy.map((s) => s.trim()).filter(Boolean);
              let index = 0;
              for (const raw of cleaned) {
                const parsed = parseSortItem(raw);
                if (!allowedSortable.has(parsed.property)) {
                  ctx.addIssue({
                    code: 'custom',
                    path: ['sortBy', index],
                    message: `sort property "${parsed.property}" is not allowed`,
                  });
                }
                index += 1;
              }
            }
          }

          // filter allowlist + operator/type validation
          for (const [field, conditions] of Object.entries(val.rawFilters)) {
            const cfg = filterable[field];

            if (!cfg) {
              ctx.addIssue({
                code: 'custom',
                path: ['rawFilters', field],
                message: `filter field "${field}" is not allowed`,
              });
              continue;
            }

            const allowedOps = filterableOps.get(field) ?? new Set<Operator>();

            let index = 0;
            for (const cond of conditions) {
              if (!allowedOps.has(cond.op)) {
                ctx.addIssue({
                  code: 'custom',
                  path: ['rawFilters', field, index, 'op'],
                  message: `operator "${cond.op}" is not allowed for "${field}"`,
                });
              }

              const typeError = validateConditionType(cfg.type, cond, field);
              if (typeError) {
                ctx.addIssue({
                  code: 'custom',
                  path: ['rawFilters', field, index],
                  message: typeError,
                });
              }

              index += 1;
            }
          }

          // group consistency
          const hasAnyFilter = Object.keys(val.rawFilters).length > 0;
          const hasAnyGroupDef = Object.keys(val.groupDefs).length > 0;

          if (hasAnyGroupDef && !hasAnyFilter) {
            ctx.addIssue({
              code: 'custom',
              path: ['groupDefs'],
              message: `group.* is not allowed without any filter.*`,
            });
          } else if (hasAnyFilter) {
            try {
              void buildWhereAstWithGroups(val.rawFilters, val.groupDefs);
            } catch (e) {
              const message = e instanceof Error ? e.message : 'Invalid group configuration';
              ctx.addIssue({
                code: 'custom',
                path: ['groupDefs'],
                message,
              });
            }
          }
        })
        .transform((val): PaginationQueryParams<TSchema> => {
          const limit = computeLimit(val.limit, config.defaultLimit);
          const sortBy = computeSortBy(val.sortBy, config);
          const rawSelect = computeSelect(val.select, effectiveConfig);
          const select = rawSelect?.filter(
            (field): field is AllowedPath<TSchema> => typeof field === 'string',
          );

          const hasAnyFilter = Object.keys(val.rawFilters).length > 0;

          const maybeFilters = hasAnyFilter
            ? { filters: buildWhereAstWithGroups(val.rawFilters, val.groupDefs) }
            : {};

          if (config.paginationType === 'LIMIT_OFFSET') {
            return {
              pagination: {
                type: 'LIMIT_OFFSET',
                limit,
                page: val.page,
                sortBy,
                select,
                ...maybeFilters,
              },
            };
          }

          // CURSOR: coerce string cursor into number/string based on cursorProperty
          let cursor: number | string | undefined = undefined;
          if (val.cursor !== undefined) {
            cursor = coerceCursorFromProperty(config.dataSchema, config.cursorProperty, val.cursor);
          }

          return {
            pagination: {
              type: 'CURSOR',
              limit,
              cursor,
              cursorProperty: config.cursorProperty,
              sortBy,
              select,
              ...maybeFilters,
            },
          };
        }),
    );

  const sortByResponseSchema = z
    .array(
      z.object({
        property: z.string(),
        direction: SortDirectionSchema,
      }),
    )
    .optional()
    .meta({ description: 'Applied sort order' });

  const filterResponseSchema = WhereNodeSchema.optional().meta({
    description: 'Applied filter AST',
  });

  const itemsPerPageSchema = z.number().meta({ description: 'Number of items returned per page' });
  const totalItemsSchema = z
    .number()
    .meta({ description: 'Total number of items matching the query' });
  const currentPageSchema = z.number().meta({ description: 'Current page number (1-based)' });
  const totalPagesSchema = z.number().min(1).meta({ description: 'Total number of pages' });

  const LIMIT_OFFSET_META_DESC = 'Pagination metadata for limit/offset mode';
  const CURSOR_META_DESC = 'Pagination metadata for cursor mode';
  const CURSOR_VALUE_DESC = 'Cursor value pointing to the last item returned';

  function validatorSchema(
    parsed?: PaginationPayload<TSchema>,
  ): z.ZodType<PaginationResponse<TSchema, AllowedPath<TSchema>>>;
  function validatorSchema(parsed?: PaginationPayload<TSchema>): z.ZodType {
    const effectiveSelect =
      parsed?.select ?? computeSelect(undefined, effectiveConfig) ?? undefined;

    const dataItemSchema =
      effectiveSelect && effectiveSelect.length > 0
        ? projectDataSchemaPreservingUnion(config.dataSchema, effectiveSelect.map(String))
        : resolveToZodObject(config.dataSchema);

    if (config.paginationType === 'LIMIT_OFFSET') {
      return z.object({
        data: z.array(dataItemSchema),
        pagination: z
          .object({
            itemsPerPage: itemsPerPageSchema,
            totalItems: totalItemsSchema,
            currentPage: currentPageSchema,
            totalPages: totalPagesSchema,
            sortBy: sortByResponseSchema,
            filter: filterResponseSchema,
          })
          .meta({ description: LIMIT_OFFSET_META_DESC }),
      });
    }

    const cursorType = cursorSchemaFromProperty(config.dataSchema, config.cursorProperty);
    return z.object({
      data: z.array(dataItemSchema),
      pagination: z
        .object({
          itemsPerPage: itemsPerPageSchema,
          cursor: cursorType.meta({ description: CURSOR_VALUE_DESC }),
          sortBy: sortByResponseSchema,
          filter: filterResponseSchema,
        })
        .meta({ description: CURSOR_META_DESC }),
    });
  }

  const partialDataItemSchema =
    selectableStrings.length > 0
      ? projectDataSchemaPreservingUnion(config.dataSchema, selectableStrings, { partial: true })
      : resolveToZodObject(config.dataSchema);

  const responseSchema =
    config.paginationType === 'LIMIT_OFFSET'
      ? buildLimitOffsetResponseSchema(partialDataItemSchema, {
          itemsPerPage: itemsPerPageSchema,
          totalItems: totalItemsSchema,
          currentPage: currentPageSchema,
          totalPages: totalPagesSchema,
          sortBy: sortByResponseSchema,
          filter: filterResponseSchema,
          metaDescription: LIMIT_OFFSET_META_DESC,
        })
      : buildCursorResponseSchema(partialDataItemSchema, {
          itemsPerPage: itemsPerPageSchema,
          cursor: cursorSchemaFromProperty(config.dataSchema, config.cursorProperty),
          sortBy: sortByResponseSchema,
          filter: filterResponseSchema,
          metaDescription: CURSOR_META_DESC,
          cursorValueDescription: CURSOR_VALUE_DESC,
        });

  function queryParamsSchema(): z.ZodType<PaginationQueryParams<TSchema>>;
  function queryParamsSchema<TExtraShape extends z.ZodRawShape>(
    extraShape: TExtraShape,
  ): z.ZodType<PaginationQueryParams<TSchema> & z.infer<z.ZodObject<TExtraShape>>>;
  function queryParamsSchema<TExtraShape extends z.ZodRawShape>(
    extraShape?: TExtraShape,
  ): z.ZodType {
    if (!extraShape) return baseQueryParamsSchema;

    const extraSchema = z.object(extraShape);
    return z
      .object({ ...rootShape, ...extraShape })
      .catchall(z.unknown())
      .superRefine((raw, ctx) => {
        const pagResult = baseQueryParamsSchema.safeParse(raw);
        if (!pagResult.success) {
          for (const issue of pagResult.error.issues) {
            ctx.addIssue({ code: 'custom', message: issue.message, path: issue.path });
          }
        }
        const extraResult = extraSchema.safeParse(raw);
        if (!extraResult.success) {
          for (const issue of extraResult.error.issues) {
            ctx.addIssue({ code: 'custom', message: issue.message, path: issue.path });
          }
        }
      })
      .transform((raw) => ({
        ...baseQueryParamsSchema.parse(raw),
        ...extraSchema.parse(raw),
      }));
  }

  return { queryParamsSchema, validatorSchema, responseSchema };
}
