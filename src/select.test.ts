import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  select,
  findNestedDiscriminators,
  resolveToZodObject,
  getZodAtPath,
  projectDataSchema,
  projectDataSchemaPreservingUnion,
  expandSelect,
  computeSelect,
} from './select';

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

    // Array => valid
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

  it('responseSchema: deep partial — nested object fields are also optional', () => {
    const { responseSchema } = makeSelect();

    // meta present but score missing → valid (deep partial makes nested fields optional)
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, meta: {} }],
      }),
    ).not.toThrow();

    // meta present with score → also valid
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, meta: { score: 42 } }],
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

/* ---------------------------------- */
/* Discriminated union support       */
/* ---------------------------------- */

describe('select with ZodDiscriminatedUnion', () => {
  const VideoSchema = z.object({
    type: z.literal('video'),
    id: z.number(),
    name: z.string(),
    duration: z.number(),
  });

  const AudioSchema = z.object({
    type: z.literal('audio'),
    id: z.number(),
    name: z.string(),
    bitrate: z.number(),
  });

  const MediaSchema = z.discriminatedUnion('type', [VideoSchema, AudioSchema]);

  // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
  function makeUnionSelect() {
    return select({
      dataSchema: MediaSchema,
      selectable: ['id', 'name', 'type'],
      defaultSelect: ['id', 'type'],
    });
  }

  it('parses select with a discriminated union dataSchema', () => {
    const { queryParamsSchema } = makeUnionSelect();
    const parsed = queryParamsSchema().parse({ select: 'id,name,type' });
    expect(parsed.select).toEqual(['id', 'name', 'type']);
  });

  it('validates response against discriminated union', () => {
    const { validatorSchema } = makeUnionSelect();
    const schema = validatorSchema({ select: ['id', 'name', 'type'] });
    const result = schema.safeParse({ data: [{ id: 1, name: 'test', type: 'video' }] });
    expect(result.success).toBe(true);
  });

  it('builds responseSchema from discriminated union', () => {
    const { responseSchema } = makeUnionSelect();
    const result = responseSchema.safeParse({ data: [{ id: 1 }] });
    expect(result.success).toBe(true);
  });

  it('defaults select with discriminated union', () => {
    const { queryParamsSchema } = makeUnionSelect();
    const parsed = queryParamsSchema().parse({});
    expect(parsed.select).toEqual(['id', 'type']);
  });

  it('rejects select without discriminator field', () => {
    const { queryParamsSchema } = makeUnionSelect();
    const result = queryParamsSchema().safeParse({ select: 'id,name' });
    expect(result.success).toBe(false);
  });

  it('allows select=* with discriminated union', () => {
    const { queryParamsSchema } = makeUnionSelect();
    const parsed = queryParamsSchema().parse({ select: '*' });
    expect(parsed.select).toContain('type');
  });

  it('validatorSchema preserves union structure (accepts option-specific data)', () => {
    const s = select({
      dataSchema: MediaSchema,
      selectable: ['id', 'type', 'duration', 'bitrate'],
      defaultSelect: '*',
    });

    const schema = s.validatorSchema({ select: ['id', 'type', 'duration', 'bitrate'] });

    // Video item has duration but no bitrate → valid (matches Video option)
    expect(schema.safeParse({ data: [{ id: 1, type: 'video', duration: 120 }] }).success).toBe(
      true,
    );

    // Audio item has bitrate but no duration → valid (matches Audio option)
    expect(schema.safeParse({ data: [{ id: 2, type: 'audio', bitrate: 320 }] }).success).toBe(true);
  });

  it('responseSchema preserves union structure with partial per option', () => {
    const s = select({
      dataSchema: MediaSchema,
      selectable: ['id', 'type', 'duration', 'bitrate'],
      defaultSelect: '*',
    });

    // Video-like partial → valid
    expect(s.responseSchema.safeParse({ data: [{ type: 'video', duration: 120 }] }).success).toBe(
      true,
    );

    // Audio-like partial → valid
    expect(s.responseSchema.safeParse({ data: [{ type: 'audio', bitrate: 320 }] }).success).toBe(
      true,
    );

    // Partial with only id → valid (matches either option since partial)
    expect(s.responseSchema.safeParse({ data: [{ id: 1 }] }).success).toBe(true);
  });

  it('validatorSchema rejects data that matches no union option', () => {
    const s = select({
      dataSchema: MediaSchema,
      selectable: ['id', 'type', 'duration', 'bitrate'],
      defaultSelect: '*',
    });

    const schema = s.validatorSchema({ select: ['id', 'type', 'duration', 'bitrate'] });

    // Object with wrong type value → rejected by both options
    expect(schema.safeParse({ data: [{ id: 1, type: 'unknown', duration: 10 }] }).success).toBe(
      false,
    );
  });
});

/* ---------------------------------------- */
/* Nested discriminated union enforcement  */
/* ---------------------------------------- */

describe('select with nested discriminated union', () => {
  const Codec1 = z.object({ id: z.number(), name: z.string() });
  const Codec2 = z.object({ id: z.number(), title: z.string() });
  const CodecSchema = z.discriminatedUnion('type', [
    Codec1.extend({ type: z.literal('codec1') }),
    Codec2.extend({ type: z.literal('codec2') }),
  ]);

  const VideoWithCodec = z.object({
    type: z.literal('video'),
    id: z.number(),
    duration: z.number(),
    codec: CodecSchema,
  });
  const AudioOnly = z.object({
    type: z.literal('audio'),
    id: z.number(),
    bitrate: z.number(),
  });
  const MediaWithCodec = z.discriminatedUnion('type', [VideoWithCodec, AudioOnly]);

  it('rejects select with codec.id but without codec.type', () => {
    const s = select({
      dataSchema: MediaWithCodec,
      selectable: ['id', 'type', 'duration', 'bitrate', 'codec.id', 'codec.name', 'codec.type'],
      defaultSelect: ['id', 'type'],
    });
    const result = s.queryParamsSchema().safeParse({ select: 'id,type,codec.id' });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.message.includes('codec.type'))).toBe(true);
    }
  });

  it('allows select with codec.id and codec.type', () => {
    const s = select({
      dataSchema: MediaWithCodec,
      selectable: ['id', 'type', 'duration', 'bitrate', 'codec.id', 'codec.name', 'codec.type'],
      defaultSelect: ['id', 'type'],
    });
    const parsed = s.queryParamsSchema().parse({ select: 'id,type,codec.id,codec.type' });
    expect(parsed.select).toContain('codec.id');
    expect(parsed.select).toContain('codec.type');
  });

  it('allows select without any codec fields (no nested check triggered)', () => {
    const s = select({
      dataSchema: MediaWithCodec,
      selectable: ['id', 'type', 'duration', 'bitrate', 'codec.id', 'codec.name', 'codec.type'],
      defaultSelect: ['id', 'type'],
    });
    const parsed = s.queryParamsSchema().parse({ select: 'id,type,duration' });
    expect(parsed.select).toEqual(['id', 'type', 'duration']);
  });

  it('allows select=* with nested discriminated union', () => {
    const s = select({
      dataSchema: MediaWithCodec,
      selectable: ['id', 'type', 'duration', 'bitrate', 'codec.id', 'codec.name', 'codec.type'],
      defaultSelect: ['id', 'type'],
    });
    const parsed = s.queryParamsSchema().parse({ select: '*' });
    expect(parsed.select).toContain('codec.type');
  });
});

/* ---------------------------------- */
/* responseType: 'one' support    */
/* ---------------------------------- */

describe('select with responseType object', () => {
  // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
  function makeObjectSelect() {
    return select({
      dataSchema: ModelSchema,
      selectable: ['id', 'status', 'meta.score'],
      defaultSelect: '*',
      responseType: 'one',
    });
  }

  it('responseSchema: accepts a single object', () => {
    const { responseSchema } = makeObjectSelect();

    expect(() =>
      responseSchema.parse({
        data: { id: 1, status: 'active', meta: { score: 42 } },
      }),
    ).not.toThrow();
  });

  it('responseSchema: rejects an array', () => {
    const { responseSchema } = makeObjectSelect();

    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, status: 'active', meta: { score: 42 } }],
      }),
    ).toThrow();
  });

  it('validatorSchema: validates a single object', () => {
    const { validatorSchema } = makeObjectSelect();

    const v = validatorSchema({ select: ['id', 'status'] });

    expect(() => v.parse({ data: { id: 1, status: 'active' } })).not.toThrow();
  });

  it('validatorSchema: rejects an array', () => {
    const { validatorSchema } = makeObjectSelect();

    const v = validatorSchema({ select: ['id', 'status'] });

    expect(() => v.parse({ data: [{ id: 1, status: 'active' }] })).toThrow();
  });

  it('default responseType is array', () => {
    const { responseSchema } = makeSelect();

    // Array => valid
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1 }],
      }),
    ).not.toThrow();

    // Object => rejected
    expect(() =>
      responseSchema.parse({
        data: { id: 1 },
      }),
    ).toThrow();
  });
});

/* ---------------------------------- */
/* Plain z.union() support            */
/* ---------------------------------- */

describe('select with plain z.union()', () => {
  const SchemaA = z.object({ id: z.number(), name: z.string() });
  const SchemaB = z.object({ id: z.number(), title: z.string() });
  const UnionSchema = z.union([SchemaA, SchemaB]);

  it('parses select with a plain z.union() dataSchema', () => {
    const s = select({
      dataSchema: UnionSchema,
      selectable: ['id', 'name', 'title'],
      defaultSelect: ['id'],
    });
    const parsed = s.queryParamsSchema().parse({ select: 'id,name' });
    expect(parsed.select).toEqual(['id', 'name']);
  });

  it('does not require a discriminator (plain union has none)', () => {
    const s = select({
      dataSchema: UnionSchema,
      selectable: ['id', 'name'],
      defaultSelect: ['id'],
    });
    const parsed = s.queryParamsSchema().parse({ select: 'id' });
    expect(parsed.select).toEqual(['id']);
  });

  it('validatorSchema preserves union structure for plain union', () => {
    const s = select({
      dataSchema: UnionSchema,
      selectable: ['id', 'name', 'title'],
      defaultSelect: '*',
    });

    const schema = s.validatorSchema({ select: ['id', 'name', 'title'] });

    // SchemaA match → valid
    expect(schema.safeParse({ data: [{ id: 1, name: 'test' }] }).success).toBe(true);
    // SchemaB match → valid
    expect(schema.safeParse({ data: [{ id: 2, title: 'test' }] }).success).toBe(true);
  });

  it('responseSchema works with plain union (partial per option)', () => {
    const s = select({
      dataSchema: UnionSchema,
      selectable: ['id', 'name', 'title'],
      defaultSelect: '*',
    });

    expect(s.responseSchema.safeParse({ data: [{ id: 1 }] }).success).toBe(true);
    expect(s.responseSchema.safeParse({ data: [{ name: 'x' }] }).success).toBe(true);
    expect(s.responseSchema.safeParse({ data: [{ title: 'x' }] }).success).toBe(true);
  });
});

/* ---------------------------------- */
/* Helper function unit tests         */
/* ---------------------------------- */

describe('findNestedDiscriminators', () => {
  it('finds a nested discriminated union', () => {
    const CodecSchema = z.discriminatedUnion('type', [
      z.object({ type: z.literal('a'), id: z.number() }),
      z.object({ type: z.literal('b'), id: z.number() }),
    ]);
    const Schema = z.object({ id: z.number(), codec: CodecSchema });

    const result = findNestedDiscriminators(Schema);
    expect(result).toEqual([{ prefix: 'codec', discriminatorPath: 'codec.type' }]);
  });

  it('returns empty array for plain ZodObject without nested unions', () => {
    const result = findNestedDiscriminators(ModelSchema);
    expect(result).toEqual([]);
  });

  it('walks into union options to find nested discriminated unions', () => {
    const InnerUnion = z.discriminatedUnion('kind', [
      z.object({ kind: z.literal('x'), val: z.number() }),
      z.object({ kind: z.literal('y'), val: z.string() }),
    ]);
    const Opt1 = z.object({ type: z.literal('a'), nested: InnerUnion });
    const Opt2 = z.object({ type: z.literal('b'), id: z.number() });
    const TopUnion = z.discriminatedUnion('type', [Opt1, Opt2]);

    const result = findNestedDiscriminators(TopUnion);
    expect(result.some((r) => r.discriminatorPath === 'nested.kind')).toBe(true);
  });
});

describe('resolveToZodObject', () => {
  it('returns the schema directly for a ZodObject', () => {
    const result = resolveToZodObject(ModelSchema);
    expect(result.shape).toBeDefined();
    expect(result.shape.id).toBeDefined();
  });

  it('merges union options into a single ZodObject', () => {
    const A = z.object({ id: z.number(), name: z.string() });
    const B = z.object({ id: z.number(), title: z.string() });
    const result = resolveToZodObject(z.union([A, B]));
    expect(result.shape.id).toBeDefined();
    expect(result.shape.name).toBeDefined();
    expect(result.shape.title).toBeDefined();
  });
});

describe('getZodAtPath', () => {
  it('resolves a simple path', () => {
    const result = getZodAtPath(ModelSchema, 'id');
    expect(result).toBeDefined();
  });

  it('resolves a nested path', () => {
    const result = getZodAtPath(ModelSchema, 'meta.score');
    expect(result).toBeDefined();
  });

  it('throws for invalid path (missing key)', () => {
    expect(() => getZodAtPath(ModelSchema, 'nonexistent')).toThrow(/missing key/);
  });

  it('throws for invalid path (intermediate not ZodObject)', () => {
    expect(() => getZodAtPath(ModelSchema, 'id.nested')).toThrow(/not inside a ZodObject/);
  });
});

describe('projectDataSchema', () => {
  it('projects selected paths into a new ZodObject', () => {
    const result = projectDataSchema(ModelSchema, ['id', 'meta.score']);
    expect(result.shape.id).toBeDefined();
    expect(result.shape.meta).toBeDefined();
  });

  it('skips empty path segments', () => {
    const result = projectDataSchema(ModelSchema, ['id', '']);
    expect(result.shape.id).toBeDefined();
  });
});

describe('projectDataSchemaPreservingUnion', () => {
  it('projects a plain ZodObject', () => {
    const result = projectDataSchemaPreservingUnion(ModelSchema, ['id', 'status']);
    expect(result).toBeDefined();
  });

  it('projects each union option independently', () => {
    const A = z.object({ id: z.number(), name: z.string() });
    const B = z.object({ id: z.number(), title: z.string() });
    const union = z.union([A, B]);

    const result = projectDataSchemaPreservingUnion(union, ['id', 'name', 'title']);
    // Should parse SchemaA-like data
    expect(result.safeParse({ id: 1, name: 'test' }).success).toBe(true);
    // Should parse SchemaB-like data
    expect(result.safeParse({ id: 1, title: 'test' }).success).toBe(true);
  });

  it('applies deep partial when partial option is true', () => {
    const result = projectDataSchemaPreservingUnion(ModelSchema, ['id', 'meta.score'], {
      partial: true,
    });
    // All fields optional in partial mode
    expect(result.safeParse({}).success).toBe(true);
    expect(result.safeParse({ id: 1 }).success).toBe(true);
  });
});

describe('expandSelect', () => {
  it('returns undefined when selectable is empty', () => {
    const result = expandSelect(['id'], { selectable: [], defaultSelect: '*' });
    expect(result).toBeUndefined();
  });

  it('returns undefined when selectable is undefined', () => {
    const result = expandSelect(['id'], { selectable: undefined, defaultSelect: '*' });
    expect(result).toBeUndefined();
  });

  it('expands wildcard to all selectable fields', () => {
    const result = expandSelect(['*'], { selectable: ['id', 'name'], defaultSelect: '*' });
    expect(result).toEqual(['id', 'name']);
  });

  it('filters out fields not in selectable', () => {
    const result = expandSelect(['id', 'unknown'], {
      selectable: ['id', 'name'],
      defaultSelect: '*',
    });
    expect(result).toEqual(['id']);
  });
});

describe('computeSelect', () => {
  it('returns undefined when expandSelect returns undefined', () => {
    const result = computeSelect(['id'], { selectable: [], defaultSelect: '*' });
    expect(result).toBeUndefined();
  });

  it('uses defaultSelect when select is undefined', () => {
    const result = computeSelect(undefined, {
      selectable: ['id', 'name'],
      defaultSelect: ['id'],
    });
    expect(result).toEqual(['id']);
  });

  it('expands defaultSelect="*"', () => {
    const result = computeSelect(undefined, { selectable: ['id', 'name'], defaultSelect: '*' });
    expect(result).toEqual(['id', 'name']);
  });
});
