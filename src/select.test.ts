import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { select } from './select';

const ModelSchema = z.object({
  id: z.number(),
  status: z.string(),
  createdAt: z.date(),
  meta: z.object({
    score: z.number(),
  }),
});

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
function makeSelect() {
  return select({
    dataSchema: ModelSchema,
    selectable: ['id', 'status', 'meta.score'],
    defaultSelect: '*',
  });
}

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
function makeSelectWithPartialDefault() {
  return select({
    dataSchema: ModelSchema,
    selectable: ['id', 'status', 'meta.score'],
    defaultSelect: ['id', 'status'],
  });
}

describe('select', () => {
  /* ---------------------------------- */
  /* Parsing */
  /* ---------------------------------- */

  it('parses select into typed array', () => {
    const { queryParamsSchema } = makeSelect();

    const parsed = queryParamsSchema().parse({ select: 'id,status' });

    expect(parsed.select).toEqual(['id', 'status']);
  });

  it('trims whitespace and ignores empty segments', () => {
    const { queryParamsSchema } = makeSelect();

    const parsed = queryParamsSchema().parse({ select: ' id , status , ' });

    expect(parsed.select).toEqual(['id', 'status']);
  });

  it('supports nested paths (dot notation)', () => {
    const { queryParamsSchema } = makeSelect();

    const parsed = queryParamsSchema().parse({ select: 'id,meta.score' });

    expect(parsed.select).toEqual(['id', 'meta.score']);
  });

  it('expands "*" to all selectable fields', () => {
    const { queryParamsSchema } = makeSelect();

    const parsed = queryParamsSchema().parse({ select: '*' });

    expect(parsed.select).toEqual(['id', 'status', 'meta.score']);
  });

  it('falls back to defaultSelect when select is missing', () => {
    const { queryParamsSchema } = makeSelect();

    const parsed = queryParamsSchema().parse({});

    // defaultSelect: ["*"] expands to full selectable
    expect(parsed.select).toEqual(['id', 'status', 'meta.score']);
  });

  it('falls back to partial defaultSelect when select is missing', () => {
    const { queryParamsSchema } = makeSelectWithPartialDefault();

    const parsed = queryParamsSchema().parse({});

    expect(parsed.select).toEqual(['id', 'status']);
  });

  /* ---------------------------------- */
  /* Rejections */
  /* ---------------------------------- */

  it('rejects empty select (select=)', () => {
    const { queryParamsSchema } = makeSelect();

    expect(() => queryParamsSchema().parse({ select: '' })).toThrow();
  });

  it('rejects unknown fields not in selectable allowlist', () => {
    const { queryParamsSchema } = makeSelect();

    expect(() => queryParamsSchema().parse({ select: 'id,unknownField' })).toThrow();
  });

  it('rejects non-string values for select', () => {
    const { queryParamsSchema } = makeSelect();

    // select must be a string (query params are always strings in HTTP)
    expect(() => queryParamsSchema().parse({ select: 123 })).toThrow();
  });

  /* ---------------------------------- */
  /* Validator schema tests */
  /* ---------------------------------- */

  it('validator: defaultSelect "*" projects to all selectable fields', () => {
    const { queryParamsSchema, validatorSchema } = makeSelect();

    const parsed = queryParamsSchema().parse({});
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

    const parsed = queryParamsSchema().parse({ select: 'id,status' });
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

    const parsed = queryParamsSchema().parse({ select: 'id,meta.score' });
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

    const parsed = queryParamsSchema().parse({});
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

  /* ---------------------------------- */
  /* responseSchema tests */
  /* ---------------------------------- */

  it('responseSchema: validates using defaultSelect without parsed params', () => {
    const { responseSchema } = makeSelect();

    // All selectable fields present => valid
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, status: 'active', meta: { score: 42 } }],
      }),
    ).not.toThrow();
  });

  it('responseSchema: accepts partial fields (only a subset of selectable)', () => {
    const { responseSchema } = makeSelect();

    // meta.score missing => valid (responseSchema is partial)
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, status: 'active' }],
      }),
    ).not.toThrow();

    // Only id => also valid
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1 }],
      }),
    ).not.toThrow();
  });

  it('responseSchema: accepts empty data array', () => {
    const { responseSchema } = makeSelect();

    expect(() => responseSchema.parse({ data: [] })).not.toThrow();
  });

  it('responseSchema: accepts full payload that validatorSchema() also accepts', () => {
    const { responseSchema, validatorSchema } = makeSelect();

    const v = validatorSchema();
    const payload = {
      data: [{ id: 1, status: 'active', meta: { score: 42 } }],
    };

    // Both accept the same full payload
    expect(() => responseSchema.parse(payload)).not.toThrow();
    expect(() => v.parse(payload)).not.toThrow();
  });

  it('responseSchema: accepts partial data that validatorSchema() rejects', () => {
    const { responseSchema, validatorSchema } = makeSelect();

    const v = validatorSchema();
    const payload = {
      data: [{ id: 1 }],
    };

    // responseSchema is partial => accepts
    expect(() => responseSchema.parse(payload)).not.toThrow();
    // validatorSchema() uses defaultSelect "*" => requires all fields => rejects
    expect(() => v.parse(payload)).toThrow();
  });

  it('responseSchema: uses all selectable fields as partial regardless of defaultSelect', () => {
    const { responseSchema } = makeSelectWithPartialDefault();

    // id + status present => valid
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, status: 'active' }],
      }),
    ).not.toThrow();

    // only id => valid (responseSchema is partial)
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1 }],
      }),
    ).not.toThrow();

    // meta.score alone => valid (it's a selectable field)
    expect(() =>
      responseSchema.parse({
        data: [{ meta: { score: 42 } }],
      }),
    ).not.toThrow();
  });

  /* ---------------------------------- */
  /* queryParamsSchema with extra shape  */
  /* ---------------------------------- */

  it('queryParamsSchema(extra): parses extra fields alongside select', () => {
    const { queryParamsSchema } = makeSelect();

    const extended = queryParamsSchema({
      search: z.string().optional(),
      locale: z.enum(['en', 'fr']).default('en'),
    });

    const parsed = extended.parse({ select: 'id,status', search: 'alice', locale: 'fr' });

    expect(parsed.select).toEqual(['id', 'status']);
    expect(parsed.search).toBe('alice');
    expect(parsed.locale).toBe('fr');
  });

  it('queryParamsSchema(extra): applies defaults for extra fields when omitted', () => {
    const { queryParamsSchema } = makeSelect();

    const extended = queryParamsSchema({
      search: z.string().optional(),
      locale: z.enum(['en', 'fr']).default('en'),
    });

    const parsed = extended.parse({});

    expect(parsed.select).toEqual(['id', 'status', 'meta.score']);
    expect(parsed.search).toBeUndefined();
    expect(parsed.locale).toBe('en');
  });

  it('queryParamsSchema(extra): collects errors from both select and extra fields', () => {
    const { queryParamsSchema } = makeSelect();

    const extended = queryParamsSchema({
      search: z.string().min(3),
    });

    expect(() =>
      extended.parse({
        select: 'unknownField',
        search: 'ab',
      }),
    ).toThrow();
  });

  it('queryParamsSchema(extra): preserves select validation with extra fields', () => {
    const { queryParamsSchema } = makeSelect();

    const extended = queryParamsSchema({
      search: z.string().optional(),
    });

    const parsed = extended.parse({
      select: 'id,meta.score',
      search: 'test',
    });

    expect(parsed.select).toEqual(['id', 'meta.score']);
    expect(parsed.search).toBe('test');
  });
});
