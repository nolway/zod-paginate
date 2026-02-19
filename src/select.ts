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
    : T extends readonly unknown[]
      ? never
      : {
          [K in Extract<keyof T, string>]: T[K] extends Primitive | readonly unknown[]
            ? K
            : K | Join<K, Path<T[K], Prev[D]>>;
        }[Extract<keyof T, string>];

/**
 * Given a type T and a dot notation path P, resolve the type at that path.
 * For example, for T = { a: { b: string }, c: number } and P = "a.b", we would get string.
 */
export type PathValue<T, P extends string> = P extends `${infer K}.${infer Rest}`
  ? K extends keyof T
    ? PathValue<T[K], Rest>
    : never
  : P extends keyof T
    ? T[P]
    : never;

/* ---------------------------------- */
/* Schema types */
/* ---------------------------------- */

export type DataSchema = z.ZodObject<z.ZodRawShape>;
export type InferData<TSchema extends DataSchema> = z.infer<TSchema>;
export type AllowedPath<TSchema extends DataSchema> = Path<InferData<TSchema>>;

/* ---------------------------------- */
/* Select schema */
/* ---------------------------------- */

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

export interface SelectableConfig<TSchema extends DataSchema> {
  selectable?: readonly AllowedPath<TSchema>[];
  defaultSelect?: readonly (AllowedPath<TSchema> | '*')[];
}

/* ---------------------------------- */
/* Allowlist helpers */
/* ---------------------------------- */

/**
 * Find a typed AllowedPath value from a string, by matching against a typed allowlist.
 * This avoids `as`: we return the existing typed value.
 */
export function pickFromAllowlist<TSchema extends DataSchema>(
  allowlist: readonly AllowedPath<TSchema>[] | undefined,
  value: string,
): AllowedPath<TSchema> | undefined {
  if (!allowlist) return undefined;
  for (const item of allowlist) {
    if (`${item}` === value) return item;
  }
  return undefined;
}

/** Expand "*" to selectable; otherwise map through allowlist. */
export function expandSelect<TSchema extends DataSchema>(
  select: readonly string[] | undefined,
  config: SelectableConfig<TSchema>,
): readonly AllowedPath<TSchema>[] | undefined {
  if (!select) return undefined;

  if (!select.includes('*')) {
    if (!config.selectable || config.selectable.length === 0) return undefined;

    const out: AllowedPath<TSchema>[] = [];
    for (const field of select) {
      const picked = pickFromAllowlist(config.selectable, field);
      if (picked) out.push(picked);
    }
    return out;
  }

  if (config.selectable && config.selectable.length > 0) return [...config.selectable];
  return undefined;
}

export function computeSelect<TSchema extends DataSchema>(
  select: string[] | undefined,
  config: SelectableConfig<TSchema>,
): AllowedPath<TSchema>[] | undefined {
  if (select) {
    const expanded = expandSelect(select, config);
    if (!expanded) return undefined;
    return [...expanded];
  }

  if (config.defaultSelect) {
    const expanded = expandSelect(
      config.defaultSelect.map((x) => `${x}`),
      config,
    );
    if (!expanded) return undefined;
    return [...expanded];
  }

  return undefined;
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

function getObjectShape(obj: z.ZodObject<z.ZodRawShape>): Readonly<Record<string, unknown>> {
  return obj.shape;
}

export function getZodAtPath(obj: z.ZodObject<z.ZodRawShape>, path: string): z.ZodType {
  const parts = path.split('.').filter(Boolean);

  let current: unknown = obj;

  for (const p of parts) {
    if (!isZodObjectSchema(current)) {
      throw new Error(`dataSchema path "${path}" is invalid: "${p}" is not inside a ZodObject`);
    }

    const shape = getObjectShape(current);
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
  dataSchema: z.ZodObject<z.ZodRawShape>,
  selectedPaths: string[],
): z.ZodObject<z.ZodRawShape> {
  const tree: Record<string, unknown> = {};

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

    for (let i = 0; i < parts.length; i += 1) {
      const key = parts[i];
      if (!key) continue;

      const isLeaf = i === parts.length - 1;

      if (isLeaf) {
        cursor[key] = getZodAtPath(dataSchema, fullPath);
      } else {
        cursor = ensureTreeNode(cursor, key);
      }
    }
  }

  const buildObjectFromTree = (node: Record<string, unknown>): z.ZodObject<z.ZodRawShape> => {
    const shape: MutableShape = {};

    for (const [k, v] of Object.entries(node)) {
      if (isZodSchema(v)) {
        shape[k] = v;
        continue;
      }
      if (isPlainObject(v)) {
        shape[k] = buildObjectFromTree(v);
        continue;
      }
      throw new Error(`Invalid projection tree at "${k}"`);
    }

    return z.object(shape);
  };

  return buildObjectFromTree(tree);
}

/* ---------------------------------- */
/* Config */
/* ---------------------------------- */

export interface SelectConfig<TSchema extends DataSchema> {
  dataSchema: TSchema;
  selectable: readonly AllowedPath<TSchema>[];
  defaultSelect?: readonly (AllowedPath<TSchema> | '*')[];
}

/* ---------------------------------- */
/* Output */
/* ---------------------------------- */

export interface SelectQueryParams<TSchema extends DataSchema> {
  select: AllowedPath<TSchema>[];
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
 */
export function select<TSchema extends DataSchema>(
  config: SelectConfig<TSchema>,
): {
  queryParamsSchema: z.ZodType<SelectQueryParams<TSchema>>;
  validatorSchema: (parsed?: SelectQueryParams<TSchema>) => z.ZodType;
} {
  const allowedSelectable = new Set<string>();
  for (const f of config.selectable) allowedSelectable.add(`${f}`);

  const baseSchema = z.object({
    select: SelectSchema.optional(),
  });

  const queryParamsSchema: z.ZodType<SelectQueryParams<TSchema>> = z
    .record(z.string(), z.unknown())
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
          const selectForValidation =
            val.select ??
            (config.defaultSelect ? config.defaultSelect.map((x) => `${x}`) : undefined);

          if (!selectForValidation) {
            ctx.addIssue({
              code: 'custom',
              path: ['select'],
              message: 'select is required (no defaultSelect configured)',
            });
            return;
          }

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

          if (selectForValidation.includes('*')) {
            const expanded = expandSelect(selectForValidation, config);
            if (!expanded || expanded.length === 0) {
              ctx.addIssue({
                code: 'custom',
                path: ['select'],
                message: 'select "*" cannot be expanded (empty selectable)',
              });
            }
          }
        })
        .transform((val): SelectQueryParams<TSchema> => {
          const resolved = computeSelect(val.select, config);

          if (!resolved || resolved.length === 0) {
            throw new Error('select resolved to empty (this should not happen after validation)');
          }

          return { select: resolved };
        }),
    );

  const validatorSchema = (parsed?: SelectQueryParams<TSchema>): z.ZodType => {
    const effectiveSelect = parsed?.select ?? computeSelect(undefined, config) ?? undefined;

    const dataItemSchema =
      effectiveSelect && effectiveSelect.length > 0
        ? projectDataSchema(
            config.dataSchema,
            effectiveSelect.map((x) => `${x}`),
          )
        : config.dataSchema;

    return z.object({
      data: z.array(dataItemSchema),
    });
  };

  return { queryParamsSchema, validatorSchema };
}
