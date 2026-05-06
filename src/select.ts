import { z } from 'zod';

/* ---------------------------------- */
/* Typed field paths (dot notation) */
/* ---------------------------------- */

/**
 * Primitive types that we consider as leaves in the Path type. Arrays are also considered leaves, since we don't want to generate paths like "arrayField.0.someProp".
 */
type Primitive = string | number | boolean | bigint | symbol | null | undefined | Date;

/**
 * Join two path segments K and P with a dot, if both are strings. Otherwise, return never.
 */
type Join<K, P> = K extends string ? (P extends string ? `${K}.${P}` : never) : never;

/**
 * Generate dot notation paths for a given type T, up to a certain depth D (default 5).
 * For example, for { a: { b: string }, c: number }, we would generate "a", "a.b", and "c". We stop recursion at depth 0 to prevent infinite types.
 */
type Prev = [never, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/**
 * Generate dot notation paths for a given type T. For example, for { a: { b: string }, c: number }, we would generate "a", "a.b", and "c".
 */
export type Path<T, D extends number = 5> = D extends 0
  ? never
  : T extends Primitive
    ? never
    : T extends readonly (infer E)[]
      ? E extends Primitive
        ? never
        : Path<E, Prev[D]>
      : {
          [K in Extract<keyof T, string>]: T[K] extends Primitive
            ? K
            : T[K] extends readonly (infer E)[]
              ? E extends Primitive
                ? K
                : K | Join<K, Path<E, Prev[D]>>
              : K | Join<K, Path<T[K], Prev[D]>>;
        }[Extract<keyof T, string>];

/**
 * Given a type T and a dot notation path P, resolve the type at that path.
 * For example, for T = { a: { b: string }, c: number } and P = "a.b", we would get string.
 */
export type PathValue<T, P extends string> = P extends `${infer K}.${infer Rest}`
  ? K extends keyof T
    ? T[K] extends readonly (infer E)[]
      ? PathValue<E, Rest>
      : PathValue<T[K], Rest>
    : never
  : P extends keyof T
    ? T[P]
    : never;

/**
 * Like `Path` but excludes intermediate object keys — only leaf paths are produced.
 * For `{ a: { b: string }, c: number }`, generates `"a.b"` and `"c"` (not `"a"`).
 * Object fields that contain only primitives at the leaf level are still represented via their dot-paths.
 */
export type LeafPath<T, D extends number = 5> = D extends 0
  ? never
  : T extends Primitive
    ? never
    : T extends readonly (infer E)[]
      ? E extends Primitive
        ? never
        : LeafPath<E, Prev[D]>
      : {
          [K in Extract<keyof T, string>]: T[K] extends Primitive
            ? K
            : T[K] extends readonly (infer E)[]
              ? E extends Primitive
                ? K
                : K | Join<K, LeafPath<E, Prev[D]>>
              : Join<K, LeafPath<T[K], Prev[D]>>;
        }[Extract<keyof T, string>];

/* ---------------------------------- */
/* Schema types */
/* ---------------------------------- */

export type DataSchema =
  | z.ZodObject<z.ZodRawShape>
  | z.ZodDiscriminatedUnion<readonly [z.ZodObject<z.ZodRawShape>, ...z.ZodObject<z.ZodRawShape>[]]>
  | z.ZodUnion<readonly [z.ZodObject<z.ZodRawShape>, ...z.ZodObject<z.ZodRawShape>[]]>
  | z.ZodDiscriminatedUnion<
      readonly [z.ZodType<Record<string, unknown>>, ...z.ZodType<Record<string, unknown>>[]]
    >
  | z.ZodUnion<
      readonly [z.ZodType<Record<string, unknown>>, ...z.ZodType<Record<string, unknown>>[]]
    >;
export type InferData<TSchema extends DataSchema> = z.infer<TSchema>;
export type AllowedPath<TSchema extends DataSchema> = Path<InferData<TSchema>>;
export type AllowedSelectablePath<TSchema extends DataSchema> = LeafPath<InferData<TSchema>>;

/**
 * Extract the discriminator key as a string literal from a ZodDiscriminatedUnion.
 * Returns `never` for plain ZodObject or ZodUnion.
 */
export type ExtractDiscriminator<TSchema> =
  TSchema extends z.ZodDiscriminatedUnion<
    z.ZodType<Record<string, unknown>>[],
    infer D extends string
  >
    ? D
    : never;

/**
 * Evaluates to `never` when the readonly tuple `T` contains duplicate elements;
 * otherwise evaluates to `T` itself. Used to enforce unique items at the type level.
 */
type HasDuplicates<T extends readonly unknown[]> = T extends readonly [infer First, ...infer Rest]
  ? First extends Rest[number]
    ? true
    : HasDuplicates<Rest>
  : false;
export type NoDuplicates<T extends readonly unknown[]> = HasDuplicates<T> extends true ? never : T;

/**
 * Extracts the `property` values from a readonly tuple of `{ property }` objects
 * into a tuple of their property types, enabling duplicate detection on those values.
 */
type PropertyValues<T extends readonly { property: unknown }[]> = T extends readonly [
  infer First extends { property: unknown },
  ...infer Rest extends { property: unknown }[],
]
  ? [First['property'], ...PropertyValues<Rest>]
  : [];

/**
 * Evaluates to `never` when the readonly tuple `T` contains two or more objects
 * with the same `property` value; otherwise evaluates to `T` itself.
 */
export type NoDuplicateProperties<T extends readonly { property: string }[]> =
  HasDuplicates<PropertyValues<T>> extends true ? never : T;

/**
 * Enforces that `TSelectable` includes the discriminator key when `TSchema` is a `ZodDiscriminatedUnion`.
 * If the discriminator is missing, evaluates to `never`, causing a compile error.
 */
export type EnsureDiscriminatorInSelectable<
  TSchema extends DataSchema,
  TSelectable extends readonly string[],
> = [ExtractDiscriminator<TSchema>] extends [never]
  ? TSelectable
  : ExtractDiscriminator<TSchema> extends TSelectable[number]
    ? TSelectable
    : never;

/* ---------------------------------- */
/* Response schema shapes (ZodObject)  */
/* ---------------------------------- */

/**
 * Identity mapped type: converts an interface into a type alias with implicit
 * index signatures — required by Zod 4's ZodObject shape constraint.
 */
export type ZodShape<T> = { [K in keyof T]: T[K] };

interface SelectResponseSchemaShapeArrayDef {
  data: z.ZodArray<z.ZodObject<z.ZodRawShape>>;
}
interface SelectResponseSchemaShapeArrayUnionDef {
  data: z.ZodArray<
    z.ZodUnion<readonly [z.ZodObject<z.ZodRawShape>, ...z.ZodObject<z.ZodRawShape>[]]>
  >;
}
interface SelectResponseSchemaShapeObjectDef {
  data: z.ZodObject<z.ZodRawShape>;
}
interface SelectResponseSchemaShapeObjectUnionDef {
  data: z.ZodUnion<readonly [z.ZodObject<z.ZodRawShape>, ...z.ZodObject<z.ZodRawShape>[]]>;
}
export type SelectResponseSchemaShape =
  | ZodShape<SelectResponseSchemaShapeArrayDef>
  | ZodShape<SelectResponseSchemaShapeArrayUnionDef>
  | ZodShape<SelectResponseSchemaShapeObjectDef>
  | ZodShape<SelectResponseSchemaShapeObjectUnionDef>;

export type SelectResponseType = 'one' | 'many';

/**
 * Zod schema for the "select" parameter, which can be a comma-separated string.
 * It normalizes the output to an array of strings.
 */
export const SelectSchema = z
  .string()
  .transform((s) =>
    s
      .split(',')
      .map((x) => x.trim())
      .filter(Boolean),
  )
  .refine((arr) => arr.length > 0, { message: 'select cannot be empty' });

/* ---------------------------------- */
/* Select config (shared) */
/* ---------------------------------- */

/** Selectable fields configuration shared between `select()` and `paginate()` internals. */
export interface SelectableConfig<
  TSchema extends DataSchema,
  TSelect extends AllowedSelectablePath<TSchema> = AllowedSelectablePath<TSchema>,
> {
  /** Allowlist of selectable fields (dot-notation paths supported). */
  selectable?: readonly TSelect[];
  /** Default fields returned when `select` is omitted. Use `"*"` to select all. */
  defaultSelect: readonly TSelect[] | '*';
}

/** Untyped version of SelectableConfig for internal use with string arrays. */
export interface UntypedSelectableConfig {
  selectable?: readonly string[];
  defaultSelect: readonly string[] | '*';
}

/* ---------------------------------- */
/* Allowlist helpers */
/* ---------------------------------- */

/**
 * Find a typed AllowedPath value from a string, by matching against a typed allowlist.
 * This avoids `as`: we return the existing typed value.
 */
export function pickFromAllowlist<T extends string>(
  allowlist: readonly T[] | undefined,
  value: string,
): T | undefined {
  if (!allowlist) return undefined;
  for (const item of allowlist) {
    if (item === value) return item;
  }
  return undefined;
}

/** Expand "*" to selectable; otherwise map through allowlist. */
export function expandSelect<
  TSchema extends DataSchema,
  TSelect extends AllowedSelectablePath<TSchema> = AllowedSelectablePath<TSchema>,
>(
  select: readonly string[] | undefined,
  config: SelectableConfig<TSchema, TSelect>,
): readonly TSelect[] | undefined;
export function expandSelect(
  select: readonly string[] | undefined,
  config: UntypedSelectableConfig,
): readonly string[] | undefined;
export function expandSelect(
  select: readonly string[] | undefined,
  config: UntypedSelectableConfig,
): readonly string[] | undefined {
  if (!select) return undefined;

  if (!select.includes('*')) {
    if (!config.selectable || config.selectable.length === 0) return undefined;

    const out: string[] = [];
    for (const field of select) {
      const picked = pickFromAllowlist(config.selectable, field);
      if (picked) out.push(picked);
    }
    return out;
  }

  if (config.selectable && config.selectable.length > 0) return [...config.selectable];
  return undefined;
}

export function computeSelect<
  TSchema extends DataSchema,
  TSelect extends AllowedSelectablePath<TSchema> = AllowedSelectablePath<TSchema>,
>(select: string[] | undefined, config: SelectableConfig<TSchema, TSelect>): TSelect[] | undefined;
export function computeSelect(
  select: string[] | undefined,
  config: UntypedSelectableConfig,
): string[] | undefined;
export function computeSelect(
  select: string[] | undefined,
  config: UntypedSelectableConfig,
): string[] | undefined {
  if (select) {
    const expanded = expandSelect(select, config);
    if (!expanded) return undefined;
    return Array.from(new Set(expanded));
  }

  const defaultSelectArr: readonly string[] =
    config.defaultSelect === '*' ? ['*'] : config.defaultSelect;
  const expanded = expandSelect(defaultSelectArr, config);
  if (!expanded) return undefined;
  return Array.from(new Set(expanded));
}

/* ---------------------------------- */
/* Projection helpers (NO "as") */
/* ---------------------------------- */

type MutableShape = Record<string, z.ZodType>;

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function getOwnProp(obj: Record<string, unknown>, key: string): unknown {
  if (!Object.prototype.hasOwnProperty.call(obj, key)) return undefined;
  return obj[key];
}

/** Duck-typed Zod schema check. */
export function isZodSchema(v: unknown): v is z.ZodType {
  if (!isPlainObject(v)) return false;
  const parseFn = getOwnProp(v, 'parse');
  return typeof parseFn === 'function';
}

/** Duck-typed ZodObject check. */
function isZodObjectSchema(v: unknown): v is z.ZodObject<z.ZodRawShape> {
  if (!isPlainObject(v)) return false;
  const parseFn = getOwnProp(v, 'parse');
  if (typeof parseFn !== 'function') return false;
  const shape = getOwnProp(v, 'shape');
  return isPlainObject(shape);
}

/** Duck-typed check for union schemas (ZodUnion / ZodDiscriminatedUnion). */
function isZodUnionSchema(
  v: unknown,
): v is { options: (z.ZodObject<z.ZodRawShape> | z.ZodType)[] } & z.ZodType {
  if (!isPlainObject(v)) return false;
  const options = getOwnProp(v, 'options');
  if (!Array.isArray(options) || options.length === 0) return false;
  // Each option must be a ZodObject or another union
  return options.every((o) => isZodObjectSchema(o) || isZodUnionSchema(o));
}

/** Duck-typed: get the element schema from a ZodArray. Returns undefined if not a ZodArray. */
function getZodArrayElement(v: unknown): z.ZodType | undefined {
  if (!isPlainObject(v)) return undefined;
  const element = getOwnProp(v, 'element');
  if (isZodSchema(element)) return element;
  return undefined;
}

/** Try to unwrap one layer (optional, nullable, etc.) via `unwrap()` method. */
function tryZodUnwrap(v: unknown): z.ZodType | undefined {
  if (!isPlainObject(v)) return undefined;
  const fn = getOwnProp(v, 'unwrap');
  if (typeof fn !== 'function') return undefined;
  const result: unknown = fn.call(v);
  if (isZodSchema(result)) return result;
  return undefined;
}

/**
 * Resolve a schema for path traversal: unwrap optional/nullable and array wrappers
 * to reach the inner ZodObject or ZodUnion that can be traversed further.
 */
function resolveSchemaForTraversal(schema: unknown): {
  inner: unknown;
  isArray: boolean;
  isOptional: boolean;
} {
  let current = schema;
  let isArray = false;
  let isOptional = false;

  for (let i = 0; i < 10; i += 1) {
    if (isZodObjectSchema(current) || isZodUnionSchema(current)) break;

    const element = getZodArrayElement(current);
    if (element) {
      isArray = true;
      current = element;
      continue;
    }

    const unwrapped = tryZodUnwrap(current);
    if (unwrapped) {
      isOptional = true;
      current = unwrapped;
      continue;
    }

    break;
  }

  return { inner: current, isArray, isOptional };
}

/**
 * Merge a union schema's leaf ZodObjects into a single ZodObject for path traversal
 * (first-seen key wins). Returns undefined if the value is not a union schema.
 */
function mergeUnionForTraversal(v: unknown): z.ZodObject<z.ZodRawShape> | undefined {
  if (!isZodUnionSchema(v)) return undefined;
  const leaves = v.options.flatMap((option) => collectLeafObjects(option));
  const mergedShape: Record<string, z.ZodType> = {};
  for (const leaf of leaves) {
    for (const [key, value] of Object.entries(leaf.shape)) {
      if (!(key in mergedShape) && isZodSchema(value)) {
        mergedShape[key] = value;
      }
    }
  }
  return z.object(mergedShape);
}

/**
 * Recursively collect all leaf ZodObject schemas from a DataSchema.
 * Traverses nested unions (ZodUnion / ZodDiscriminatedUnion) to reach the ZodObject leaves.
 */
export function collectLeafObjects(schema: DataSchema | z.ZodType): z.ZodObject<z.ZodRawShape>[] {
  if (isZodObjectSchema(schema)) return [schema];
  if (isZodUnionSchema(schema)) {
    return schema.options.flatMap((option) => collectLeafObjects(option));
  }
  return [];
}

/**
 * Extract the discriminator key from a `z.discriminatedUnion()`.
 * Returns `undefined` for plain `z.union()` or `z.object()`.
 */
export function getDiscriminatorKey(schema: DataSchema): string | undefined {
  if (!isPlainObject(schema)) return undefined;
  const def = getOwnProp(schema, '_def');
  if (!isPlainObject(def)) return undefined;
  const disc = getOwnProp(def, 'discriminator');
  return typeof disc === 'string' ? disc : undefined;
}

/** Same as getDiscriminatorKey but accepts any value (for recursive schema walking). */
function getDiscriminatorKeyFromAny(schema: unknown): string | undefined {
  if (!isPlainObject(schema)) return undefined;
  const def = getOwnProp(schema, '_def');
  if (!isPlainObject(def)) return undefined;
  const disc = getOwnProp(def, 'discriminator');
  return typeof disc === 'string' ? disc : undefined;
}

/** Duck-typed check for union-like schemas on any value. */
function isUnionLike(v: unknown): v is { options: unknown[] } {
  if (!isPlainObject(v)) return false;
  const options = getOwnProp(v, 'options');
  return Array.isArray(options) && options.length > 0;
}

export interface NestedDiscriminator {
  prefix: string;
  discriminatorPath: string;
}

/**
 * Recursively find all nested `z.discriminatedUnion()` schemas within a DataSchema.
 * Returns an array of `{ prefix, discriminatorPath }` for each nested discriminated union.
 * For example, if `codec` is a `z.discriminatedUnion("type", ...)`, returns
 * `[{ prefix: "codec", discriminatorPath: "codec.type" }]`.
 *
 * Also detects top-level discriminators from nested union levels.
 * E.g. `discriminatedUnion('status', [ discriminatedUnion('materialType', [obj, ...]) ])`
 * returns both `{ prefix: '', discriminatorPath: 'status' }` and
 * `{ prefix: '', discriminatorPath: 'materialType' }`.
 */
export function findNestedDiscriminators(schema: DataSchema): NestedDiscriminator[] {
  const results: NestedDiscriminator[] = [];

  function walkObject(obj: unknown, prefix: string): void {
    if (!isZodObjectSchema(obj)) return;
    const shape = obj.shape;
    for (const [key, value] of Object.entries(shape)) {
      if (!isZodSchema(value)) continue;
      const fullPath = prefix ? `${prefix}.${key}` : key;
      const disc = getDiscriminatorKeyFromAny(value);
      if (disc) {
        results.push({ prefix: fullPath, discriminatorPath: `${fullPath}.${disc}` });
        // Recurse into each option of this nested union
        if (isUnionLike(value)) {
          for (const option of value.options) {
            walkObject(option, fullPath);
          }
        }
      } else if (isZodObjectSchema(value)) {
        walkObject(value, fullPath);
      }
    }
  }

  if (isZodObjectSchema(schema)) {
    walkObject(schema, '');
  } else if (isZodUnionSchema(schema)) {
    // Collect discriminator keys from all union levels (including nested unions)
    const unionDiscs = collectUnionDiscriminators(schema, '');
    results.push(...unionDiscs);
    // Walk leaf objects for nested discriminated union fields
    const leaves = collectLeafObjects(schema);
    for (const leaf of leaves) {
      walkObject(leaf, '');
    }
  }

  return results;
}

/**
 * Recursively collect discriminator keys from nested union levels.
 * For `discriminatedUnion('status', [discriminatedUnion('materialType', [...])])`,
 * this produces `{ prefix: '', discriminatorPath: 'status' }` and
 * `{ prefix: '', discriminatorPath: 'materialType' }`.
 */
function collectUnionDiscriminators(
  schema: unknown,
  prefix: string,
  results: NestedDiscriminator[] = [],
  seen = new Set<string>(),
): NestedDiscriminator[] {
  const disc = getDiscriminatorKeyFromAny(schema);
  if (disc) {
    const path = prefix ? `${prefix}.${disc}` : disc;
    if (!seen.has(path)) {
      seen.add(path);
      results.push({ prefix, discriminatorPath: path });
    }
  }
  if (isUnionLike(schema)) {
    for (const option of schema.options) {
      if (!isZodObjectSchema(option)) {
        // Nested union — recurse at the same prefix level
        collectUnionDiscriminators(option, prefix, results, seen);
      }
    }
  }
  return results;
}

/**
 * If the schema is a ZodObject, return it directly.
 * If the schema is a ZodUnion / ZodDiscriminatedUnion (possibly nested),
 * collect all leaf ZodObject shapes and merge them into a single ZodObject (first-seen key wins).
 */
export function resolveToZodObject(schema: DataSchema): z.ZodObject<z.ZodRawShape> {
  if (isZodObjectSchema(schema)) return schema;

  if (isZodUnionSchema(schema)) {
    const leaves = collectLeafObjects(schema);
    const mergedShape: Record<string, z.ZodType> = {};
    for (const leaf of leaves) {
      const shape = leaf.shape;
      for (const [key, value] of Object.entries(shape)) {
        if (!(key in mergedShape) && isZodSchema(value)) {
          mergedShape[key] = value;
        }
      }
    }
    return z.object(mergedShape);
  }

  throw new Error(
    'dataSchema must be a ZodObject or a ZodUnion/ZodDiscriminatedUnion of ZodObjects',
  );
}

function getObjectShape(obj: z.ZodObject<z.ZodRawShape>): Readonly<Record<string, unknown>> {
  return obj.shape;
}

/** Check whether a dot-path resolves successfully inside a single ZodObject. */
function hasPathInObject(obj: z.ZodObject<z.ZodRawShape>, path: string): boolean {
  const parts = path.split('.').filter(Boolean);
  let current: unknown = obj;
  for (const p of parts) {
    const { inner } = resolveSchemaForTraversal(current);
    current = inner;
    const resolved = isZodObjectSchema(current) ? current : mergeUnionForTraversal(current);
    if (!resolved) return false;
    const shape = getObjectShape(resolved);
    const next = shape[p];
    if (!next || !isZodSchema(next)) return false;
    current = next;
  }
  return true;
}

/**
 * Recursively apply `.optional()` to all properties of a ZodObject,
 * descending into nested ZodObject shapes.
 */
function deepPartial(schema: z.ZodObject<z.ZodRawShape>): z.ZodObject<z.ZodRawShape> {
  const shape: MutableShape = {};
  for (const [key, value] of Object.entries(schema.shape)) {
    if (!isZodSchema(value)) continue;
    if (isZodObjectSchema(value)) {
      shape[key] = deepPartial(value).optional();
    } else {
      shape[key] = value.optional();
    }
  }
  return z.object(shape);
}

/**
 * Project a DataSchema preserving the union structure (including nested unions).
 * - ZodObject → delegates to `projectDataSchema`.
 * - ZodUnion / ZodDiscriminatedUnion → projects each option independently
 *   (paths that don't exist in a given option are skipped) and returns `z.union([...])`.
 *   If an option is itself a union, recurse into it preserving the nested structure.
 *
 * When `partial` is true, a recursive deep partial is applied to each projected option
 * **before** wrapping in the union, so you get
 * `z.union([deepPartial(OptionA), deepPartial(OptionB)])` instead of a single merged partial.
 */

/** Internal helper: project a nested union that may not match the DataSchema type exactly. */
function projectNestedUnion(
  schema: { options: (z.ZodObject<z.ZodRawShape> | z.ZodType)[] } & z.ZodType,
  selectedPaths: string[],
  opts?: { partial?: boolean },
): z.ZodType {
  const projected: z.ZodType[] = schema.options.map((option) => {
    if (isZodUnionSchema(option) && !isZodObjectSchema(option)) {
      return projectNestedUnion(option, selectedPaths, opts);
    }
    if (!isZodObjectSchema(option)) {
      throw new Error('Union option is neither a ZodObject nor a ZodUnion');
    }
    const validPaths = selectedPaths.filter((p) => hasPathInObject(option, p));
    const obj = validPaths.length > 0 ? projectDataSchema(option, validPaths) : z.object({});
    return opts?.partial ? deepPartial(obj) : obj;
  });

  const first = projected[0];
  const second = projected[1];
  if (!first || !second) {
    throw new Error('Union must have at least 2 options');
  }
  return z.union([first, second, ...projected.slice(2)]);
}

export function projectDataSchemaPreservingUnion(
  dataSchema: DataSchema,
  selectedPaths: string[],
  options?: { partial?: boolean },
): z.ZodType {
  if (isZodObjectSchema(dataSchema)) {
    const projected = projectDataSchema(dataSchema, selectedPaths);
    return options?.partial ? deepPartial(projected) : projected;
  }

  if (isZodUnionSchema(dataSchema)) {
    return projectNestedUnion(dataSchema, selectedPaths, options);
  }

  throw new Error(
    'dataSchema must be a ZodObject or a ZodUnion/ZodDiscriminatedUnion of ZodObjects',
  );
}

export function getZodAtPath(obj: DataSchema, path: string): z.ZodType {
  const parts = path.split('.').filter(Boolean);

  let current: unknown = resolveToZodObject(obj);

  for (const p of parts) {
    const { inner } = resolveSchemaForTraversal(current);
    current = inner;

    const resolved = isZodObjectSchema(current) ? current : mergeUnionForTraversal(current);
    if (!resolved) {
      throw new Error(`dataSchema path "${path}" is invalid: "${p}" is not inside a ZodObject`);
    }

    const shape = getObjectShape(resolved);
    const next = shape[p];

    if (!next) throw new Error(`dataSchema path "${path}" is invalid: missing key "${p}"`);
    if (!isZodSchema(next)) {
      throw new Error(`dataSchema path "${path}" is invalid: "${p}" is not a Zod schema`);
    }

    current = next;
  }

  if (!isZodSchema(current)) {
    throw new Error(`dataSchema path "${path}" is invalid: resolved value is not a Zod schema`);
  }

  return current;
}

export function projectDataSchema(
  dataSchema: DataSchema,
  selectedPaths: string[],
): z.ZodObject<z.ZodRawShape> {
  type UnionSchema = { options: (z.ZodObject<z.ZodRawShape> | z.ZodType)[] } & z.ZodType;

  const tree: Record<string, unknown> = {};
  const arrayPaths = new Set<string>();
  const optionalPaths = new Set<string>();
  const unionAtPath = new Map<string, UnionSchema>();

  const ensureTreeNode = (node: Record<string, unknown>, key: string): Record<string, unknown> => {
    const existing = node[key];

    if (existing === undefined) {
      const child: Record<string, unknown> = {};
      node[key] = child;
      return child;
    }

    if (isPlainObject(existing)) return existing;

    if (isZodSchema(existing)) {
      throw new Error(`Cannot project "${key}": "${key}" is selected as a leaf and as an object`);
    }

    throw new Error(`Cannot project "${key}": conflicting selection`);
  };

  for (const fullPath of selectedPaths) {
    const parts = fullPath.split('.').filter(Boolean);
    if (parts.length === 0) continue;

    let cursor = tree;

    // Walk the original schema alongside the tree to detect array/optional wrappers
    let schemaWalk: unknown = resolveToZodObject(dataSchema);

    for (let i = 0; i < parts.length; i += 1) {
      const key = parts[i];
      if (!key) continue;

      const isLeaf = i === parts.length - 1;

      // Resolve schemaWalk to a traversable ZodObject (or merge union for traversal)
      const { inner } = resolveSchemaForTraversal(schemaWalk);
      schemaWalk = inner;
      if (!isZodObjectSchema(schemaWalk)) {
        const merged = mergeUnionForTraversal(schemaWalk);
        if (merged) schemaWalk = merged;
      }

      if (isZodObjectSchema(schemaWalk)) {
        const shape = getObjectShape(schemaWalk);
        const rawField = shape[key];

        if (rawField && isZodSchema(rawField)) {
          const partialPath = parts.slice(0, i + 1).join('.');
          const wrapInfo = resolveSchemaForTraversal(rawField);
          if (wrapInfo.isArray) arrayPaths.add(partialPath);
          if (wrapInfo.isOptional) optionalPaths.add(partialPath);

          // Track nested unions at intermediate paths so buildObjectFromTree
          // can preserve the union structure instead of merging into a single object.
          if (!isLeaf && isZodUnionSchema(wrapInfo.inner)) {
            unionAtPath.set(partialPath, wrapInfo.inner);
          }

          // Advance schema walk to the unwrapped inner for next iteration
          schemaWalk = isLeaf ? rawField : wrapInfo.inner;
        }
      }

      if (isLeaf) {
        cursor[key] = getZodAtPath(dataSchema, fullPath);
      } else {
        cursor = ensureTreeNode(cursor, key);
      }
    }
  }

  /** Collect leaf dot-paths from a projection tree node. */
  const collectTreePaths = (node: Record<string, unknown>, prefix = ''): string[] => {
    const paths: string[] = [];
    for (const [key, value] of Object.entries(node)) {
      const path = prefix ? `${prefix}.${key}` : key;
      if (isZodSchema(value)) {
        paths.push(path);
      } else if (isPlainObject(value)) {
        paths.push(...collectTreePaths(value, path));
      }
    }
    return paths;
  };

  const buildObjectFromTree = (
    node: Record<string, unknown>,
    parentPath: string,
  ): z.ZodObject<z.ZodRawShape> => {
    const shape: MutableShape = {};

    for (const [k, v] of Object.entries(node)) {
      const childPath = parentPath ? `${parentPath}.${k}` : k;

      if (isZodSchema(v)) {
        shape[k] = v;
        continue;
      }
      if (isPlainObject(v)) {
        const nestedUnion = unionAtPath.get(childPath);
        let built: z.ZodType;
        if (nestedUnion) {
          // Preserve the nested union structure by projecting each option independently.
          const subPaths = collectTreePaths(v);
          built = projectNestedUnion(nestedUnion, subPaths);
        } else {
          built = buildObjectFromTree(v, childPath);
        }
        if (arrayPaths.has(childPath)) built = z.array(built);
        if (optionalPaths.has(childPath)) built = built.optional();
        shape[k] = built;
        continue;
      }
      throw new Error(`Invalid projection tree at "${k}"`);
    }

    return z.object(shape);
  };

  return buildObjectFromTree(tree, '');
}

/* ---------------------------------- */
/* Config */
/* ---------------------------------- */

/** Configuration for the `select()` factory. */
export interface SelectConfig<
  TSchema extends DataSchema,
  TSelect extends AllowedSelectablePath<TSchema> = AllowedSelectablePath<TSchema>,
  TResponseType extends SelectResponseType = 'many',
> {
  /** Zod schema representing one data item (object, discriminated union, or union). */
  dataSchema: TSchema;
  /** Allowlist of selectable fields (dot-notation paths supported). */
  selectable: readonly TSelect[];
  /** Fields that are decorative (added manually, not from DB). Subset of selectable. */
  decorative?: readonly TSelect[];
  /** Default fields returned when `select` is omitted from the query. Use `"*"` to select all. */
  defaultSelect: readonly TSelect[] | '*';
  /** Shape of `data` in the response: `"many"` returns an array, `"one"` returns a single object. @default "many" */
  responseType?: TResponseType;
}

/* ---------------------------------- */
/* Output */
/* ---------------------------------- */

/**
 * Extract the top-level key from a dot-path.
 * e.g. `'meta.score'` → `'meta'`, `'id'` → `'id'`.
 */
export type TopLevelKey<P extends string> = P extends `${infer K}.${string}` ? K : P;

/**
 * Projected data item: exposes only the selectable keys of the original schema
 * with `unknown` values. This gives consumers key auto-completion
 * without requiring `as` (projectDataSchema erases value types at runtime).
 */
export type ProjectedData<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
> = Partial<Record<TopLevelKey<TSelect> & keyof InferData<TSchema>, unknown>>;

/**
 * Typed projected data item: like `ProjectedData` but resolves value types
 * via `PathValue`. For top-level paths the value type is exact; for nested
 * dot-paths (e.g. `'meta.score'`) the top-level key is typed as the full
 * nested object (not the leaf), so partial nested projections may be wider
 * than the runtime shape. Use this when you need value-level type safety
 * and accept that trade-off.
 */
export type TypedProjectedData<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
> = {
  [K in TopLevelKey<TSelect> & keyof InferData<TSchema>]?: InferData<TSchema>[K];
};

export interface SelectQueryPayload<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
  TResponseType extends SelectResponseType = SelectResponseType,
> {
  fields: TSelect[];
  /** Subset of `fields` that are decorative (not from DB, added manually). */
  decorativeFields?: TSelect[];
  responseType: TResponseType;
}

/** Shorthand for `SelectQueryPayload` with `responseType: 'one'`. */
export type SelectOneQueryPayload<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
> = SelectQueryPayload<TSchema, TSelect, 'one'>;

/** Shorthand for `SelectQueryPayload` with `responseType: 'many'`. */
export type SelectManyQueryPayload<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
> = SelectQueryPayload<TSchema, TSelect, 'many'>;

export interface SelectQueryParams<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
  TResponseType extends SelectResponseType = SelectResponseType,
> {
  select: SelectQueryPayload<TSchema, TSelect, TResponseType>;
}

export type SelectResponseData<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema>,
  TResponseType extends SelectResponseType,
> = TResponseType extends 'one'
  ? TypedProjectedData<TSchema, TSelect>
  : TypedProjectedData<TSchema, TSelect>[];

export interface SelectResponse<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
  TResponseType extends SelectResponseType = 'many',
> {
  data: SelectResponseData<TSchema, TSelect, TResponseType>;
}

/** Shorthand for `SelectResponse` with `responseType: 'one'` (data is a single object). */
export type SelectOneResponse<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
> = SelectResponse<TSchema, TSelect, 'one'>;

/** Shorthand for `SelectResponse` with `responseType: 'many'` (data is an array). */
export type SelectManyResponse<
  TSchema extends DataSchema,
  TSelect extends AllowedPath<TSchema> = AllowedPath<TSchema>,
> = SelectResponse<TSchema, TSelect>;

/**
 * Result type returned by `select()`. Use this instead of
 * `ReturnType<typeof select>` to preserve the generic `TSchema`.
 *
 * @example
 * function createSelector(): SelectResult<typeof MySchema> {
 *   return select({ dataSchema: MySchema, … });
 * }
 */
export interface SelectResult<
  TSchema extends DataSchema,
  TSelectable extends AllowedSelectablePath<TSchema> = AllowedSelectablePath<TSchema>,
  TResponseType extends SelectResponseType = SelectResponseType,
> {
  queryParamsSchema: {
    (): z.ZodType<SelectQueryParams<TSchema, TSelectable, TResponseType>>;
    <TExtraShape extends z.ZodRawShape>(
      extraShape: TExtraShape,
    ): z.ZodType<
      SelectQueryParams<TSchema, TSelectable, TResponseType> & z.infer<z.ZodObject<TExtraShape>>
    >;
  };
  validatorSchema: (
    parsed?: SelectQueryPayload<TSchema, TSelectable>,
  ) => z.ZodType<SelectResponse<TSchema, TSelectable, TResponseType>>;
  responseSchema: z.ZodObject<SelectResponseSchemaShape>;
  responseType: TResponseType;
}

/* ---------------------------------- */
/* Factory */
/* ---------------------------------- */

/**
 * Generate Zod schemas and runtime validators for select-only query parameters, based on a config object.
 * @param config The configuration object defining the selectable fields.
 * @returns An object containing:
 *   - `queryParamsSchema`: A Zod schema for validating and parsing the raw query parameters.
 *   - `validatorSchema`: A function that takes the already-parsed query parameters and returns a Zod schema for validating the response.
 *   - `responseSchema`: A pre-built Zod schema for validating the response (uses defaultSelect or all selectable fields).
 */
export function select<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedSelectablePath<TSchema>[],
  const TDefaultSelect extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
>(
  config: Omit<
    SelectConfig<TSchema, TSelectable[number], 'one'>,
    'selectable' | 'defaultSelect' | 'decorative'
  > & {
    /** Allowlist of selectable fields (dot-notation paths). Enables the `select` query parameter. */
    selectable: NoDuplicates<TSelectable> & EnsureDiscriminatorInSelectable<TSchema, TSelectable>;
    /** Fields that are decorative (added manually, not from DB). Subset of selectable. */
    decorative?: readonly NoInfer<TSelectable[number]>[];
    /** Default fields returned when `select` is omitted. Use `"*"` to select all. */
    defaultSelect: NoDuplicates<TDefaultSelect> | '*';
    /** Shape of `data` in the response: `"one"` returns a single object. */
    responseType: 'one';
  },
): SelectResult<TSchema, TSelectable[number], 'one'>;

export function select<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedSelectablePath<TSchema>[],
  const TDefaultSelect extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
>(
  config: Omit<
    SelectConfig<TSchema, TSelectable[number]>,
    'selectable' | 'defaultSelect' | 'decorative'
  > & {
    /** Allowlist of selectable fields (dot-notation paths). Enables the `select` query parameter. */
    selectable: NoDuplicates<TSelectable> & EnsureDiscriminatorInSelectable<TSchema, TSelectable>;
    /** Fields that are decorative (added manually, not from DB). Subset of selectable. */
    decorative?: readonly NoInfer<TSelectable[number]>[];
    /** Default fields returned when `select` is omitted. Use `"*"` to select all. */
    defaultSelect: NoDuplicates<TDefaultSelect> | '*';
    /** Shape of `data` in the response: `"many"` returns an array (default). */
    responseType?: 'many';
  },
): SelectResult<TSchema, TSelectable[number], 'many'>;

export function select<
  TSchema extends DataSchema,
  const TSelectable extends readonly AllowedSelectablePath<TSchema>[],
  const TDecorative extends readonly NoInfer<TSelectable[number]>[] = readonly [],
  const TDefaultSelect extends readonly NoInfer<TSelectable[number]>[] = readonly NoInfer<
    TSelectable[number]
  >[],
>(
  config: Omit<
    SelectConfig<TSchema, TSelectable[number], SelectResponseType>,
    'selectable' | 'defaultSelect' | 'decorative'
  > & {
    /** Allowlist of selectable fields (dot-notation paths). Enables the `select` query parameter. */
    selectable: NoDuplicates<TSelectable> & EnsureDiscriminatorInSelectable<TSchema, TSelectable>;
    /** Fields that are decorative (added manually, not from DB). Subset of selectable. */
    decorative?: NoDuplicates<TDecorative>;
    /** Default fields returned when `select` is omitted. Use `"*"` to select all. */
    defaultSelect: NoDuplicates<TDefaultSelect> | '*';
  },
): SelectResult<TSchema, TSelectable[number]> {
  const responseType: SelectResponseType = config.responseType ?? 'many';
  const discriminatorKey = getDiscriminatorKey(config.dataSchema);
  const nestedDiscriminators = findNestedDiscriminators(config.dataSchema);

  const selectableStrings: string[] = [...config.selectable];
  const decorativeSet = new Set<string>((config.decorative ?? []).map(String));

  const effectiveConfig: UntypedSelectableConfig = {
    selectable: selectableStrings,
    defaultSelect: config.defaultSelect === '*' ? '*' : Array.from(config.defaultSelect, String),
  };

  const allowedSelectable = new Set<string>(selectableStrings);

  const baseSchema = z.object({
    select: SelectSchema.optional(),
  });

  const selectableList = selectableStrings.join(', ');
  const defaultSelectDesc =
    config.defaultSelect === '*' ? '*' : [...config.defaultSelect].join(',');

  const rootShape: Record<string, z.ZodType> = {
    select: z
      .string()
      .optional()
      .meta({
        description: `Comma-separated list of fields to include in the response. Allowed: ${selectableList}. Use "*" to select all. Default: ${defaultSelectDesc}`,
        example: defaultSelectDesc,
      }),
  };

  const baseQueryParamsSchema: z.ZodType<SelectQueryParams<TSchema, TSelectable[number]>> = z
    .object(rootShape)
    .catchall(z.unknown())
    .transform((q): Record<string, unknown> => {
      const raw = q.select;
      return {
        ...q,
        select: typeof raw === 'string' ? raw : undefined,
      };
    })
    .pipe(
      baseSchema
        .superRefine((val, ctx): void => {
          const selectForValidation: readonly string[] =
            val.select ??
            (effectiveConfig.defaultSelect === '*' ? ['*'] : effectiveConfig.defaultSelect);

          const hasWildcard = selectForValidation.includes('*');

          let index = 0;
          for (const field of selectForValidation) {
            if (field === '*') {
              index += 1;
              continue;
            }

            if (!allowedSelectable.has(field)) {
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
                message: 'select "*" cannot be expanded (empty selectable)',
              });
            }
          }

          if (discriminatorKey && !hasWildcard && !selectForValidation.includes(discriminatorKey)) {
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
        })
        .transform((val): SelectQueryParams<TSchema, TSelectable[number]> => {
          const resolved = computeSelect(val.select, effectiveConfig);

          if (!resolved || resolved.length === 0) {
            throw new Error('select resolved to empty (this should not happen after validation)');
          }

          // Safe: resolved values come from config.selectable (discriminator enforced at type level).
          // plus the discriminator key (which is a valid AllowedPath<TSchema> at runtime).
          const typedSelect: TSelectable[number][] = resolved.filter(
            (field): field is TSelectable[number] => typeof field === 'string',
          );

          const decorativeFields = typedSelect.filter((f) => decorativeSet.has(String(f)));
          return {
            select: {
              fields: typedSelect,
              ...(decorativeFields.length > 0 ? { decorativeFields } : {}),
              responseType,
            },
          };
        }),
    );

  function validatorSchema(
    parsed?: SelectQueryPayload<TSchema, TSelectable[number]>,
  ): z.ZodType<SelectResponse<TSchema, TSelectable[number], SelectResponseType>>;
  function validatorSchema(parsed?: SelectQueryPayload<TSchema, TSelectable[number]>): z.ZodType {
    const effectiveSelect =
      parsed?.fields ?? computeSelect(undefined, effectiveConfig) ?? undefined;

    const dataItemSchema: z.ZodType =
      effectiveSelect && effectiveSelect.length > 0
        ? projectDataSchemaPreservingUnion(config.dataSchema, effectiveSelect.map(String))
        : resolveToZodObject(config.dataSchema);

    const dataSchema = responseType === 'one' ? dataItemSchema : z.array(dataItemSchema);
    const schema: z.ZodType = z.object({ data: dataSchema });
    return schema;
  }

  const dataItemSchema: z.ZodType =
    selectableStrings.length > 0
      ? projectDataSchemaPreservingUnion(config.dataSchema, selectableStrings, { partial: true })
      : resolveToZodObject(config.dataSchema);
  const dataSchemaForResponse = responseType === 'one' ? dataItemSchema : z.array(dataItemSchema);

  function buildResponseSchema(): z.ZodObject<SelectResponseSchemaShape>;
  function buildResponseSchema(): z.ZodType {
    return z.object({ data: dataSchemaForResponse });
  }
  const responseSchema = buildResponseSchema();

  function queryParamsSchema(): z.ZodType<SelectQueryParams<TSchema, TSelectable[number]>>;
  function queryParamsSchema<TExtraShape extends z.ZodRawShape>(
    extraShape: TExtraShape,
  ): z.ZodType<SelectQueryParams<TSchema, TSelectable[number]> & z.infer<z.ZodObject<TExtraShape>>>;
  function queryParamsSchema<TExtraShape extends z.ZodRawShape>(
    extraShape?: TExtraShape,
  ): z.ZodType {
    if (!extraShape) return baseQueryParamsSchema;

    const extraSchema = z.object(extraShape);
    return z
      .object({ ...rootShape, ...extraShape })
      .catchall(z.unknown())
      .superRefine((raw, ctx) => {
        const baseResult = baseQueryParamsSchema.safeParse(raw);
        if (!baseResult.success) {
          for (const issue of baseResult.error.issues) {
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

  return {
    queryParamsSchema,
    validatorSchema,
    responseSchema,
    responseType,
  };
}
