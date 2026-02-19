import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { select, SelectQueryParams } from './select';

const ModelSchema = z.object({
  id: z.number(),
  status: z.string(),
  createdAt: z.date(),
  meta: z.object({
    score: z.number(),
  }),
});

function makeSelect(): {
  queryParamsSchema: z.ZodType<SelectQueryParams<typeof ModelSchema>>;
  validatorSchema: (parsed?: SelectQueryParams<typeof ModelSchema>) => z.ZodType;
} {
  return select({
    dataSchema: ModelSchema,
    selectable: ['id', 'status', 'createdAt', 'meta.score'],
    defaultSelect: ['*'],
  });
}

function makeSelectNoDefault(): {
  queryParamsSchema: z.ZodType<SelectQueryParams<typeof ModelSchema>>;
  validatorSchema: (parsed?: SelectQueryParams<typeof ModelSchema>) => z.ZodType;
} {
  return select({
    dataSchema: ModelSchema,
    selectable: ['id', 'status', 'createdAt', 'meta.score'],
  });
}

function makeSelectWithPartialDefault(): {
  queryParamsSchema: z.ZodType<SelectQueryParams<typeof ModelSchema>>;
  validatorSchema: (parsed?: SelectQueryParams<typeof ModelSchema>) => z.ZodType;
} {
  return select({
    dataSchema: ModelSchema,
    selectable: ['id', 'status', 'createdAt', 'meta.score'],
    defaultSelect: ['id', 'createdAt'],
  });
}

describe('select', () => {
  /* ---------------------------------- */
  /* Parsing */
  /* ---------------------------------- */

  it('parses select into typed array', () => {
    const { queryParamsSchema } = makeSelect();

    const parsed = queryParamsSchema.parse({ select: 'id,status' });

    expect(parsed.select).toEqual(['id', 'status']);
  });

  it('trims whitespace and ignores empty segments', () => {
    const { queryParamsSchema } = makeSelect();

    const parsed = queryParamsSchema.parse({ select: ' id , status , ' });

    expect(parsed.select).toEqual(['id', 'status']);
  });

  it('supports nested paths (dot notation)', () => {
    const { queryParamsSchema } = makeSelect();

    const parsed = queryParamsSchema.parse({ select: 'id,meta.score' });

    expect(parsed.select).toEqual(['id', 'meta.score']);
  });

  it('expands "*" to all selectable fields', () => {
    const { queryParamsSchema } = makeSelect();

    const parsed = queryParamsSchema.parse({ select: '*' });

    expect(parsed.select).toEqual(['id', 'status', 'createdAt', 'meta.score']);
  });

  it('falls back to defaultSelect when select is missing', () => {
    const { queryParamsSchema } = makeSelect();

    const parsed = queryParamsSchema.parse({});

    // defaultSelect: ["*"] expands to full selectable
    expect(parsed.select).toEqual(['id', 'status', 'createdAt', 'meta.score']);
  });

  it('falls back to partial defaultSelect when select is missing', () => {
    const { queryParamsSchema } = makeSelectWithPartialDefault();

    const parsed = queryParamsSchema.parse({});

    expect(parsed.select).toEqual(['id', 'createdAt']);
  });

  /* ---------------------------------- */
  /* Rejections */
  /* ---------------------------------- */

  it('rejects empty select (select=)', () => {
    const { queryParamsSchema } = makeSelect();

    expect(() => queryParamsSchema.parse({ select: '' })).toThrow();
  });

  it('rejects unknown fields not in selectable allowlist', () => {
    const { queryParamsSchema } = makeSelect();

    expect(() => queryParamsSchema.parse({ select: 'id,unknownField' })).toThrow();
  });

  it('rejects when no select provided and no defaultSelect configured', () => {
    const { queryParamsSchema } = makeSelectNoDefault();

    expect(() => queryParamsSchema.parse({})).toThrow();
  });

  it('ignores non-string values for select', () => {
    const { queryParamsSchema } = makeSelect();

    // select is not a string => falls back to defaultSelect
    const parsed = queryParamsSchema.parse({ select: 123 });

    expect(parsed.select).toEqual(['id', 'status', 'createdAt', 'meta.score']);
  });

  /* ---------------------------------- */
  /* Validator schema tests */
  /* ---------------------------------- */

  it('validator: defaultSelect "*" projects to all selectable fields', () => {
    const { queryParamsSchema, validatorSchema } = makeSelect();

    const parsed = queryParamsSchema.parse({});
    const v = validatorSchema(parsed);

    // All fields present => valid
    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
            status: 'active',
            createdAt: new Date('2022-01-01T00:00:00Z'),
            meta: { score: 42 },
          },
        ],
      }),
    ).not.toThrow();

    // Missing meta => invalid (meta.score is projected)
    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
            status: 'active',
            createdAt: new Date('2022-01-01T00:00:00Z'),
          },
        ],
      }),
    ).toThrow();
  });

  it('validator: explicit select narrows the expected data shape', () => {
    const { queryParamsSchema, validatorSchema } = makeSelect();

    const parsed = queryParamsSchema.parse({ select: 'id,status' });
    const v = validatorSchema(parsed);

    // id + status present => valid
    expect(() =>
      v.parse({
        data: [{ id: 1, status: 'active' }],
      }),
    ).not.toThrow();

    // status missing => invalid
    expect(() =>
      v.parse({
        data: [{ id: 1 }],
      }),
    ).toThrow();
  });

  it('validator: nested path projection works correctly', () => {
    const { queryParamsSchema, validatorSchema } = makeSelect();

    const parsed = queryParamsSchema.parse({ select: 'id,meta.score' });
    const v = validatorSchema(parsed);

    // id + meta.score present => valid
    expect(() =>
      v.parse({
        data: [{ id: 1, meta: { score: 42 } }],
      }),
    ).not.toThrow();

    // meta missing => invalid
    expect(() =>
      v.parse({
        data: [{ id: 1 }],
      }),
    ).toThrow();

    // meta.score missing => invalid
    expect(() =>
      v.parse({
        data: [{ id: 1, meta: {} }],
      }),
    ).toThrow();
  });

  it('validator: called without parsed uses defaultSelect', () => {
    const { validatorSchema } = makeSelect();

    const v = validatorSchema();

    // defaultSelect ["*"] => all fields expected
    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
            status: 'active',
            createdAt: new Date('2022-01-01T00:00:00Z'),
            meta: { score: 42 },
          },
        ],
      }),
    ).not.toThrow();
  });

  it('validator: partial defaultSelect projects only those fields', () => {
    const { queryParamsSchema, validatorSchema } = makeSelectWithPartialDefault();

    const parsed = queryParamsSchema.parse({});
    const v = validatorSchema(parsed);

    // id + createdAt present => valid
    expect(() =>
      v.parse({
        data: [{ id: 1, createdAt: new Date('2022-01-01T00:00:00Z') }],
      }),
    ).not.toThrow();

    // createdAt missing => invalid
    expect(() =>
      v.parse({
        data: [{ id: 1 }],
      }),
    ).toThrow();
  });

  it('validator: data must be an array', () => {
    const { validatorSchema } = makeSelect();

    const v = validatorSchema();

    expect(() => v.parse({ data: 'not an array' })).toThrow();
    expect(() => v.parse({})).toThrow();
  });

  it('validator: empty data array is valid', () => {
    const { validatorSchema } = makeSelect();

    const v = validatorSchema();

    expect(() => v.parse({ data: [] })).not.toThrow();
  });
});
