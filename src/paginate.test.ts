import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { paginate, type PaginateResult } from './paginate';

/**
 * Zod model used to validate Path<T> / projection / cursor type.
 * Keep it small to avoid TS depth issues.
 */
const ModelSchema = z.object({
  id: z.number(),
  status: z.string(),
  createdAt: z.date(),
  meta: z.object({
    score: z.number(),
  }),
});

function makeLimitOffset(): PaginateResult<typeof ModelSchema> {
  return paginate({
    paginationType: 'LIMIT_OFFSET',
    dataSchema: ModelSchema,
    selectable: ['id', 'status', 'createdAt', 'meta.score'],
    sortable: ['createdAt', 'id'],
    filterable: {
      status: { type: 'string', ops: ['$eq', '$ilike'] },
      createdAt: { type: 'date', ops: ['$btw', '$null', '$eq', '$gt', '$lte'] },
      id: { type: 'number', ops: ['$gt', '$in', '$eq'] },
      'meta.score': { type: 'number', ops: ['$gte', '$lte'] },
    },
    defaultSortBy: [{ property: 'createdAt', direction: 'DESC' }],
    defaultLimit: 20,
    maxLimit: 100,
    defaultSelect: '*',
  });
}

function makeCursor(): PaginateResult<typeof ModelSchema> {
  return paginate({
    paginationType: 'CURSOR',
    dataSchema: ModelSchema,
    cursorProperty: 'id',
    selectable: ['id', 'status', 'createdAt', 'meta.score'],
    sortable: ['createdAt', 'id'],
    filterable: {
      status: { type: 'string', ops: ['$eq'] },
      createdAt: { type: 'date', ops: ['$btw', '$null'] },
      id: { type: 'number', ops: ['$gt', '$in'] },
    },
    defaultLimit: 10,
    maxLimit: 50,
    defaultSelect: ['id', 'createdAt'],
  });
}

describe('paginate', () => {
  it('parses LIMIT_OFFSET pagination, converts limit/page strings to numbers', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      limit: '10',
      page: '2',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.limit).toBe(10);
      expect(parsed.pagination.page).toBe(2);
    }
  });

  it('applies defaultLimit when limit is missing', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      page: '1',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.limit).toBe(20);
      expect(parsed.pagination.page).toBe(1);
    }
  });

  it('enforces maxLimit', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        limit: '999',
        page: '1',
      }),
    ).toThrow();
  });

  it('normalizes sortBy: string -> array, and parses SortItem', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      sortBy: 'createdAt:DESC',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.sortBy).toEqual([{ property: 'createdAt', direction: 'DESC' }]);
    }
  });

  it('normalizes sortBy: string[] stays array and parses multiple items', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      sortBy: ['createdAt:DESC', 'id:ASC'],
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.sortBy).toEqual([
        { property: 'createdAt', direction: 'DESC' },
        { property: 'id', direction: 'ASC' },
      ]);
    }
  });

  it('filters empty sortBy values (e.g. ?sortBy=)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      sortBy: ['  ', 'createdAt:DESC'],
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.sortBy).toEqual([{ property: 'createdAt', direction: 'DESC' }]);
    }
  });

  it('sortBy with only empty values falls back to defaultSortBy', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      sortBy: ['   ', ' '],
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.sortBy).toEqual([{ property: 'createdAt', direction: 'DESC' }]);
    }
  });

  it('applies defaultSortBy when sortBy is missing', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      page: '1',
      limit: '10',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.sortBy).toEqual([{ property: 'createdAt', direction: 'DESC' }]);
    }
  });

  it('parses select and enforces selectable allowlist', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      select: 'id,status',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.select).toEqual(['id', 'status']);
    }

    expect(() =>
      queryParamsSchema().parse({
        select: 'id,unknownField',
      }),
    ).toThrow();
  });

  it('expands select="*" using selectable + uses defaultSelect when missing', () => {
    const { queryParamsSchema } = makeLimitOffset();

    // Missing select -> defaultSelect ["*"] -> expand to selectable list
    const parsed = queryParamsSchema().parse({
      limit: '10',
      page: '1',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.select).toEqual(['id', 'status', 'createdAt', 'meta.score']);
    }

    // Explicit "*"
    const parsed2 = queryParamsSchema().parse({
      select: '*',
    });

    expect(parsed2.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed2.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed2.pagination.select).toEqual(['id', 'status', 'createdAt', 'meta.score']);
    }
  });

  it('normalizes filter.<field> string -> string[] and builds filters AST', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.status': '$eq:active',
      'filter.id': '$gt:10',
    });

    expect(parsed.pagination.filters).toBeTruthy();
    expect(parsed.pagination.filters?.type).toBeDefined();
  });

  it('supports $not as prefix: $not:$null', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.createdAt': '$not:$null',
    });

    const root = parsed.pagination.filters;

    const collect = (n: typeof root): { field: string; not?: boolean; op: string }[] => {
      if (n?.type === 'filter')
        return [{ field: n.field, not: n.condition.not, op: n.condition.op }];
      return n?.items.flatMap(collect) ?? [];
    };

    const leaves = collect(root);
    const createdAt = leaves.find((x) => x.field === 'createdAt');
    expect(createdAt).toBeTruthy();
    expect(createdAt?.op).toBe('$null');
    expect(createdAt?.not).toBe(true);
  });

  it('rejects filter fields not in filterable allowlist', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.unknown': '$eq:test',
      }),
    ).toThrow();
  });

  it('rejects operators not allowed for a field (runtime)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$gt:10',
      }),
    ).toThrow();
  });

  it('rejects type mismatch on comparable ops: date field with number bounds vs ISO date', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.createdAt': '$gt:123',
      }),
    ).toThrow();

    expect(() =>
      queryParamsSchema().parse({
        'filter.id': '$gt:2022-01-01',
      }),
    ).toThrow();
  });

  it('rejects $btw when bounds are not same kind (number vs date)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.createdAt': '$btw:2022-01-01,10',
      }),
    ).toThrow();
  });

  it('supports $btw for date fields when ISO bounds are valid', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.createdAt': '$btw:2022-01-01,2022-01-10',
    });

    expect(parsed.pagination.filters).toBeTruthy();
  });

  it('supports $in for number fields (value is array of strings in DSL)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.id': '$in:1,2,3',
    });

    const root = parsed.pagination.filters;

    const collectOps = (n: typeof root): string[] => {
      if (n?.type === 'filter') return [n.condition.op];
      return n?.items.flatMap(collectOps) ?? [];
    };

    expect(collectOps(root)).toContain('$in');
  });

  it('supports groups via $g:<id> and group.<id>.* definitions', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.status': ['$g:1:$eq:active', '$g:1:$or:$eq:postponed'],
      'filter.createdAt': ['$g:2:$not:$null', '$g:2:$and:$btw:2022-01-01,2022-02-01'],

      'group.1.parent': '0',
      'group.2.parent': '0',
      'group.2.join': '$and',
    });

    expect(parsed.pagination.filters).toBeTruthy();
    expect(parsed.pagination.filters?.type).toBe('and');
  });

  it('rejects invalid group defs: group.0.parent is forbidden', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$eq:active',
        'group.0.parent': '1',
      }),
    ).toThrow();
  });

  it('LIMIT_OFFSET: rejects cursor param', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        cursor: 'abc',
      }),
    ).toThrow();
  });

  it('CURSOR pagination: rejects page and includes cursorProperty in output', () => {
    const { queryParamsSchema } = makeCursor();

    expect(() =>
      queryParamsSchema().parse({
        page: '1',
        cursor: '123',
      }),
    ).toThrow();

    const parsed = queryParamsSchema().parse({
      cursor: '123',
      limit: '5',
    });

    expect(parsed.pagination.type).toBe('CURSOR');
    if (parsed.pagination.type === 'CURSOR') {
      expect(parsed.pagination.cursor).toBe(123);
      expect(parsed.pagination.limit).toBe(5);
      expect(parsed.pagination.cursorProperty).toBe('id');
    }
  });

  it('CURSOR pagination: applies defaultLimit when limit missing', () => {
    const { queryParamsSchema } = makeCursor();

    const parsed = queryParamsSchema().parse({
      cursor: '123',
    });

    expect(parsed.pagination.type).toBe('CURSOR');
    if (parsed.pagination.type === 'CURSOR') {
      expect(parsed.pagination.limit).toBe(10);
    }
  });

  it('select empty string (select=) is rejected', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        select: '',
      }),
    ).toThrow();
  });

  it('sortBy invalid direction is rejected', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        sortBy: 'createdAt:DOWN',
      }),
    ).toThrow();
  });

  it('filter invalid operator is rejected', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$wat:active',
      }),
    ).toThrow();
  });

  it('rejects first condition in a group having a combinator ($or / $and)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': ['$g:1:$or:$eq:active'],
      }),
    ).toThrow();
  });

  it('rejects first child group having a join operator', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$g:1:$eq:active',
        'group.1.parent': '0',
        'group.1.join': '$and',
      }),
    ).toThrow();
  });

  it('rejects cyclic group definitions', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$g:1:$eq:active',
        'group.1.parent': '2',
        'group.2.parent': '1',
      }),
    ).toThrow();
  });

  it('resolves sibling groups in numeric order (deterministic folding)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.status': ['$g:2:$eq:active'],
      'filter.id': ['$g:10:$eq:1'],

      'group.2.parent': '0',
      'group.10.parent': '0',
      'group.10.join': '$or',
    });

    const root = parsed.pagination.filters;

    expect(root?.type).toBe('or');
  });

  it('rejects invalid $btw format (missing bound)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.createdAt': '$btw:2022-01-01',
      }),
    ).toThrow();
  });

  it('rejects invalid $not usage without operator', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$not:',
      }),
    ).toThrow();
  });

  it('supports nested group tree', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      // Group 1: status active
      'filter.status': '$g:1:$eq:active',

      // Group 2: (id > 10 OR id > 20), attached to group 1 with AND
      'filter.id': ['$g:2:$gt:10', '$g:2:$or:$gt:20'],

      'group.1.parent': '0',
      'group.1.op': '$and',

      'group.2.parent': '1',
      'group.2.join': '$and',
    });

    const root = parsed.pagination.filters;

    expect(root).toBeTruthy();
    expect(root?.type).toBe('and');
  });

  it('rejects unknown group id format (non-integer)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$g:abc:$eq:active',
      }),
    ).toThrow();
  });

  it('rejects invalid group join value', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$g:1:$eq:active',
        'group.1.parent': '0',
        'group.1.join': '$xor',
      }),
    ).toThrow();
  });

  /* ---------------------------------- */
  /* Validator schema tests (response validation) */
  /* ---------------------------------- */

  it('validator (LIMIT_OFFSET): defaultSelect "*" projects to selectable fields', () => {
    const { queryParamsSchema, validatorSchema } = makeLimitOffset();

    // defaultSelect ["*"] should expand to selectable
    const parsed = queryParamsSchema().parse({ page: '1', limit: '10' });

    const v = validatorSchema(parsed.pagination);

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
        pagination: {
          itemsPerPage: 10,
          totalItems: 1,
          currentPage: 1,
          totalPages: 1,
        },
      }),
    ).not.toThrow();

    // Missing projected nested object (meta.score) should fail
    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
            status: 'active',
            createdAt: new Date('2022-01-01T00:00:00Z'),
            // meta missing
          },
        ],
        pagination: {
          itemsPerPage: 10,
          totalItems: 1,
          currentPage: 1,
          totalPages: 1,
        },
      }),
    ).toThrow();
  });

  it('validator (LIMIT_OFFSET): explicit select narrows the expected data shape', () => {
    const { queryParamsSchema, validatorSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      select: 'id,status',
      page: '1',
      limit: '10',
    });

    const v = validatorSchema(parsed.pagination);

    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
            status: 'active',
          },
        ],
        pagination: {
          itemsPerPage: 10,
          totalItems: 1,
          currentPage: 1,
          totalPages: 1,
        },
      }),
    ).not.toThrow();

    // status missing => fail (since projected schema requires it)
    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
          },
        ],
        pagination: {
          itemsPerPage: 10,
          totalItems: 1,
          currentPage: 1,
          totalPages: 1,
        },
      }),
    ).toThrow();
  });

  it('validator (CURSOR): defaultSelect projects to defaultSelect + cursor type inferred from cursorProperty', () => {
    const { queryParamsSchema, validatorSchema } = makeCursor();

    const parsed = queryParamsSchema().parse({
      cursor: '123',
    });

    const v = validatorSchema(parsed.pagination);

    // ✅ cursor accepts number
    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
            createdAt: new Date('2022-01-01T00:00:00Z'),
          },
        ],
        pagination: {
          itemsPerPage: 10,
          cursor: 123,
        },
      }),
    ).not.toThrow();

    // ✅ cursor accepts ISO number
    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
            createdAt: new Date('2022-01-01T00:00:00Z'),
          },
        ],
        pagination: {
          itemsPerPage: 10,
          cursor: 1,
        },
      }),
    ).not.toThrow();

    // ❌ cursor should NOT accept object
    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
            createdAt: new Date('2022-01-01T00:00:00Z'),
          },
        ],
        pagination: {
          itemsPerPage: 10,
          cursor: { nope: true },
        },
      }),
    ).toThrow();
  });

  it('validator (CURSOR): explicit select changes expected item shape', () => {
    const { queryParamsSchema, validatorSchema } = makeCursor();

    const parsed = queryParamsSchema().parse({
      cursor: '123',
      select: 'id,status,createdAt',
    });

    const v = validatorSchema(parsed.pagination);

    // should require id + status + createdAt
    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
            status: 'active',
            createdAt: new Date(),
          },
        ],
        pagination: {
          itemsPerPage: 10,
          cursor: 123,
        },
      }),
    ).not.toThrow();

    // status missing => fail
    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
          },
        ],
        pagination: {
          itemsPerPage: 10,
          cursor: 123,
        },
      }),
    ).toThrow();
  });

  it('CURSOR pagination: coerces numeric cursor string to number (helper example)', () => {
    const { queryParamsSchema } = makeCursor();

    const parsed = queryParamsSchema().parse({
      cursor: '123', // querystring input is always string
    });

    expect(parsed.pagination.type).toBe('CURSOR');
    if (parsed.pagination.type !== 'CURSOR') return;

    const raw = parsed.pagination.cursor; // string | undefined

    // Coerce only when it's a numeric string
    let coerced: string | number | undefined = raw;

    if (typeof raw === 'string') {
      const s = raw.trim();
      if (/^[+-]?\d+(\.\d+)?$/.test(s)) {
        coerced = Number(s);
      }
    }

    expect(coerced).toBe(123);
    expect(typeof coerced).toBe('number');
  });

  it('does not include pagination.filters when no filter.* is provided', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      limit: '10',
      page: '1',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type !== 'LIMIT_OFFSET') return;

    // ✅ property should not exist at all
    expect('filters' in parsed.pagination).toBe(false);
    expect(parsed.pagination.filters).toBeUndefined();
  });

  it('rejects group.* without any filter.*', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        // no filter.*
        'group.1.parent': '0',
        'group.1.join': '$and',
      }),
    ).toThrow();
  });

  it('CURSOR: does not include pagination.filters when no filter.* is provided', () => {
    const { queryParamsSchema } = makeCursor();

    const parsed = queryParamsSchema().parse({
      cursor: '123',
      limit: '5',
    });

    expect(parsed.pagination.type).toBe('CURSOR');
    if (parsed.pagination.type !== 'CURSOR') return;

    expect('filters' in parsed.pagination).toBe(false);
    expect(parsed.pagination.filters).toBeUndefined();
  });

  /* ---------------------------------- */
  /* responseSchema tests */
  /* ---------------------------------- */

  it('LIMIT_OFFSET responseSchema: validates a complete response without parsed params', () => {
    const { responseSchema } = makeLimitOffset();

    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, status: 'active', createdAt: new Date(), meta: { score: 10 } }],
        pagination: {
          itemsPerPage: 20,
          totalItems: 1,
          currentPage: 1,
          totalPages: 1,
        },
      }),
    ).not.toThrow();
  });

  it('LIMIT_OFFSET responseSchema: accepts partial data fields', () => {
    const { responseSchema } = makeLimitOffset();

    // Only id => valid (responseSchema uses partial data schema)
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1 }],
        pagination: {
          itemsPerPage: 20,
          totalItems: 1,
          currentPage: 1,
          totalPages: 1,
        },
      }),
    ).not.toThrow();
  });

  it('LIMIT_OFFSET responseSchema: accepts empty data array', () => {
    const { responseSchema } = makeLimitOffset();

    expect(() =>
      responseSchema.parse({
        data: [],
        pagination: {
          itemsPerPage: 20,
          totalItems: 0,
          currentPage: 1,
          totalPages: 1,
        },
      }),
    ).not.toThrow();
  });

  it('LIMIT_OFFSET responseSchema: accepts full payload and partial payload', () => {
    const { responseSchema, validatorSchema } = makeLimitOffset();

    const fullPayload = {
      data: [{ id: 1, status: 'ok', createdAt: new Date(), meta: { score: 5 } }],
      pagination: { itemsPerPage: 20, totalItems: 1, currentPage: 1, totalPages: 1 },
    };

    const partialPayload = {
      data: [{ id: 1 }],
      pagination: { itemsPerPage: 20, totalItems: 1, currentPage: 1, totalPages: 1 },
    };

    // responseSchema accepts both full and partial
    expect(() => responseSchema.parse(fullPayload)).not.toThrow();
    expect(() => responseSchema.parse(partialPayload)).not.toThrow();

    // validatorSchema() (default select "*") requires all fields
    expect(() => validatorSchema().parse(fullPayload)).not.toThrow();
    expect(() => validatorSchema().parse(partialPayload)).toThrow();
  });

  it('CURSOR responseSchema: validates a complete cursor response', () => {
    const { responseSchema } = makeCursor();

    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, status: 'active', createdAt: new Date(), meta: { score: 10 } }],
        pagination: {
          itemsPerPage: 10,
          cursor: 1,
        },
      }),
    ).not.toThrow();
  });

  it('CURSOR responseSchema: rejects non-number cursor when cursorProperty is number', () => {
    const { responseSchema } = makeCursor();

    expect(() =>
      responseSchema.parse({
        data: [],
        pagination: {
          itemsPerPage: 10,
          cursor: 'not-a-number',
        },
      }),
    ).toThrow();
  });

  describe('decorative fields', () => {
    it('decorativeSelect is undefined when no decorative config is set', () => {
      const { queryParamsSchema } = paginate({
        paginationType: 'LIMIT_OFFSET',
        dataSchema: ModelSchema,
        selectable: ['id', 'status', 'createdAt', 'meta.score'],
        defaultLimit: 20,
        maxLimit: 100,
        defaultSelect: '*',
      });

      const parsed = queryParamsSchema().parse({ select: '*' });

      expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
      expect(parsed.pagination.decorativeSelect).toBeUndefined();
    });

    it('decorativeSelect is undefined when no decorative field is in the actual select', () => {
      const { queryParamsSchema } = paginate({
        paginationType: 'LIMIT_OFFSET',
        dataSchema: ModelSchema,
        decorative: ['status'],
        selectable: ['id', 'status', 'createdAt', 'meta.score'],
        defaultLimit: 20,
        maxLimit: 100,
        defaultSelect: '*',
      });

      const parsed = queryParamsSchema().parse({ select: 'id,createdAt' });

      expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
      expect(parsed.pagination.decorativeSelect).toBeUndefined();
    });

    it('includes decorativeSelect when decorative fields are requested', () => {
      const { queryParamsSchema } = paginate({
        paginationType: 'LIMIT_OFFSET',
        dataSchema: ModelSchema,
        decorative: ['status'],
        selectable: ['id', 'status', 'createdAt', 'meta.score'],
        defaultLimit: 20,
        maxLimit: 100,
        defaultSelect: '*',
      });

      const parsed = queryParamsSchema().parse({ select: '*' });

      expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
      expect(parsed.pagination.decorativeSelect).toEqual(['status']);
    });

    it('includes only the subset of decorative fields that are actually selected', () => {
      const { queryParamsSchema } = paginate({
        paginationType: 'LIMIT_OFFSET',
        dataSchema: ModelSchema,
        decorative: ['status', 'meta.score'],
        selectable: ['id', 'status', 'createdAt', 'meta.score'],
        defaultLimit: 20,
        maxLimit: 100,
        defaultSelect: '*',
      });

      const parsed = queryParamsSchema().parse({ select: 'id,status' });

      expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
      expect(parsed.pagination.decorativeSelect).toEqual(['status']);
    });

    it('decorativeSelect works with CURSOR pagination', () => {
      const { queryParamsSchema } = paginate({
        paginationType: 'CURSOR',
        dataSchema: ModelSchema,
        cursorProperty: 'id',
        decorative: ['status'],
        selectable: ['id', 'status', 'createdAt', 'meta.score'],
        defaultLimit: 20,
        maxLimit: 100,
        defaultSelect: '*',
      });

      const parsed = queryParamsSchema().parse({ select: '*' });

      expect(parsed.pagination.type).toBe('CURSOR');
      expect(parsed.pagination.decorativeSelect).toEqual(['status']);
    });

    it('decorative fields cannot appear in sortable', () => {
      const { queryParamsSchema } = paginate({
        paginationType: 'LIMIT_OFFSET',
        dataSchema: ModelSchema,
        decorative: ['status'],
        selectable: ['id', 'status', 'createdAt', 'meta.score'],
        sortable: ['id', 'createdAt'],
        defaultLimit: 20,
        maxLimit: 100,
        defaultSelect: '*',
      });

      const result = queryParamsSchema().safeParse({ sortBy: 'status:ASC' });
      expect(result.success).toBe(false);
    });

    it('decorativeSelect in defaultSelect', () => {
      const { queryParamsSchema } = paginate({
        paginationType: 'LIMIT_OFFSET',
        dataSchema: ModelSchema,
        decorative: ['status'],
        selectable: ['id', 'status', 'createdAt', 'meta.score'],
        defaultLimit: 20,
        maxLimit: 100,
        defaultSelect: ['id', 'status'],
      });

      const parsed = queryParamsSchema().parse({});

      expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
      expect(parsed.pagination.decorativeSelect).toEqual(['status']);
    });
  });
});

/* ---------------------------------- */
/* PaginationType narrowing            */
/* ---------------------------------- */

describe('PaginationType narrowing', () => {
  it('LIMIT_OFFSET: z.infer narrows pagination to LimitOffsetPaginationResponseMeta', () => {
    const lo = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: ModelSchema,
      selectable: ['id', 'status'],
      sortable: ['id'],
      defaultLimit: 10,
      maxLimit: 100,
      defaultSelect: ['id', 'status'],
    });

    type Response = z.infer<typeof lo.responseSchema>;
    type PaginationMeta = Response['pagination'];

    // Statically, totalItems exists on the narrowed type (no union)
    const check: PaginationMeta = {
      itemsPerPage: 10,
      totalItems: 1,
      currentPage: 1,
      totalPages: 1,
    };
    expect(check.totalItems).toBe(1);

    // Runtime validation works
    const parsed = lo.responseSchema.parse({
      data: [{ id: 1, status: 'ok' }],
      pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
    });
    expect(parsed.pagination).toHaveProperty('totalItems');
  });

  it('CURSOR: z.infer narrows pagination to CursorPaginationResponseMeta', () => {
    const cur = paginate({
      paginationType: 'CURSOR',
      dataSchema: ModelSchema,
      cursorProperty: 'id',
      selectable: ['id', 'status'],
      sortable: ['id'],
      defaultLimit: 10,
      maxLimit: 100,
      defaultSelect: ['id', 'status'],
    });

    type Response = z.infer<typeof cur.responseSchema>;
    type PaginationMeta = Response['pagination'];

    // Statically, cursor exists on the narrowed type (no union)
    const check: PaginationMeta = {
      itemsPerPage: 10,
      cursor: 42,
    };
    expect(check.cursor).toBe(42);

    // Runtime validation works
    const parsed = cur.responseSchema.parse({
      data: [{ id: 1, status: 'ok' }],
      pagination: { itemsPerPage: 10, cursor: 1 },
    });
    expect(parsed.pagination).toHaveProperty('cursor');
  });

  it('LIMIT_OFFSET: queryParamsSchema narrows payload to LimitOffsetPaginationPayload', () => {
    const _lo = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: ModelSchema,
      selectable: ['id'],
      sortable: ['id'],
      defaultLimit: 5,
      maxLimit: 50,
      defaultSelect: ['id'],
    });
    expect(_lo).toBeDefined();

    type QP = z.infer<ReturnType<typeof _lo.queryParamsSchema>>;
    type Payload = QP['pagination'];

    // Statically, page exists on the narrowed payload (no union)
    const check: Payload = {
      type: 'LIMIT_OFFSET',
      limit: 5,
      page: 1,
    };
    expect(check.type).toBe('LIMIT_OFFSET');
  });

  it('CURSOR: queryParamsSchema narrows payload to CursorPaginationPayload', () => {
    const _cur = paginate({
      paginationType: 'CURSOR',
      dataSchema: ModelSchema,
      cursorProperty: 'id',
      selectable: ['id'],
      sortable: ['id'],
      defaultLimit: 5,
      maxLimit: 50,
      defaultSelect: ['id'],
    });
    expect(_cur).toBeDefined();

    type QP = z.infer<ReturnType<typeof _cur.queryParamsSchema>>;
    type Payload = QP['pagination'];

    // Statically, cursorProperty exists on the narrowed payload (no union)
    const check: Payload = {
      type: 'CURSOR',
      cursorProperty: 'id',
      limit: 5,
      cursor: 42,
    };
    expect(check.type).toBe('CURSOR');
  });

  it('PaginateResult<…, "LIMIT_OFFSET"> is assignable from paginate() return', () => {
    // Explicit return type annotation with TType works
    function make(): PaginateResult<typeof ModelSchema, 'LIMIT_OFFSET'> {
      return paginate({
        paginationType: 'LIMIT_OFFSET',
        dataSchema: ModelSchema,
        selectable: ['id', 'status'],
        sortable: ['id'],
        defaultLimit: 10,
        maxLimit: 100,
        defaultSelect: ['id', 'status'],
      });
    }

    const { responseSchema } = make();
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, status: 'ok' }],
        pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
      }),
    ).not.toThrow();
  });

  it('PaginateResult<…, "CURSOR"> is assignable from paginate() return', () => {
    function make(): PaginateResult<typeof ModelSchema, 'CURSOR'> {
      return paginate({
        paginationType: 'CURSOR',
        dataSchema: ModelSchema,
        cursorProperty: 'id',
        selectable: ['id', 'status'],
        sortable: ['id'],
        defaultLimit: 10,
        maxLimit: 100,
        defaultSelect: ['id', 'status'],
      });
    }

    const { responseSchema } = make();
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, status: 'ok' }],
        pagination: { itemsPerPage: 10, cursor: 1 },
      }),
    ).not.toThrow();
  });

  it('backward compat: PaginateResult without TType still works (union)', () => {
    // This is the existing pattern — no TType specified
    function make(): PaginateResult<typeof ModelSchema> {
      return paginate({
        paginationType: 'LIMIT_OFFSET',
        dataSchema: ModelSchema,
        selectable: ['id', 'status'],
        sortable: ['id'],
        defaultLimit: 10,
        maxLimit: 100,
        defaultSelect: ['id', 'status'],
      });
    }

    const { responseSchema } = make();
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, status: 'ok' }],
        pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
      }),
    ).not.toThrow();
  });
});

/* ---------------------------------- */
/* Discriminated union support       */
/* ---------------------------------- */

describe('paginate with ZodDiscriminatedUnion', () => {
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

  function makeUnionLimitOffset(): PaginateResult<typeof MediaSchema, 'LIMIT_OFFSET'> {
    return paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: MediaSchema,
      selectable: ['id', 'name', 'type'],
      defaultSelect: ['id', 'type'],
      defaultLimit: 20,
      maxLimit: 100,
    });
  }

  function makeUnionCursor(): PaginateResult<typeof MediaSchema, 'CURSOR'> {
    return paginate({
      paginationType: 'CURSOR',
      dataSchema: MediaSchema,
      cursorProperty: 'id',
      selectable: ['id', 'name', 'type'],
      defaultSelect: '*',
      defaultLimit: 10,
      maxLimit: 50,
    });
  }

  it('parses query params with limit-offset pagination', () => {
    const { queryParamsSchema } = makeUnionLimitOffset();
    const parsed = queryParamsSchema().parse({
      select: 'id,name,type',
      limit: '10',
      page: '1',
    });
    expect(parsed.pagination.select).toEqual(['id', 'name', 'type']);
    expect(parsed.pagination.limit).toBe(10);
    expect(parsed.pagination.page).toBe(1);
  });

  it('validates response with limit-offset pagination', () => {
    const { queryParamsSchema, validatorSchema } = makeUnionLimitOffset();
    const parsed = queryParamsSchema().parse({
      select: 'id,name,type',
      limit: '10',
      page: '1',
    });
    const schema = validatorSchema(parsed.pagination);
    const result = schema.safeParse({
      data: [{ id: 1, name: 'test', type: 'video' }],
      pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
    });
    expect(result.success).toBe(true);
  });

  it('builds responseSchema from discriminated union (limit-offset)', () => {
    const { responseSchema } = makeUnionLimitOffset();
    const result = responseSchema.safeParse({
      data: [{ id: 1 }],
      pagination: { itemsPerPage: 20, totalItems: 1, currentPage: 1, totalPages: 1 },
    });
    expect(result.success).toBe(true);
  });

  it('parses query params with cursor pagination', () => {
    const { queryParamsSchema } = makeUnionCursor();
    const parsed = queryParamsSchema().parse({ select: 'id,name,type', limit: '5' });
    expect(parsed.pagination.select).toEqual(['id', 'name', 'type']);
    expect(parsed.pagination.limit).toBe(5);
  });

  it('validates response with cursor pagination', () => {
    const { queryParamsSchema, validatorSchema } = makeUnionCursor();
    const parsed = queryParamsSchema().parse({ select: 'id,name,type', limit: '5' });
    const schema = validatorSchema(parsed.pagination);
    const result = schema.safeParse({
      data: [{ id: 1, name: 'clip', type: 'video' }],
      pagination: { itemsPerPage: 5, cursor: 1 },
    });
    expect(result.success).toBe(true);
  });

  it('builds responseSchema from discriminated union (cursor)', () => {
    const { responseSchema } = makeUnionCursor();
    const result = responseSchema.safeParse({
      data: [{ id: 1, name: 'clip', type: 'video' }],
      pagination: { itemsPerPage: 10, cursor: 1 },
    });
    expect(result.success).toBe(true);
  });

  it('defaults select with discriminated union', () => {
    const { queryParamsSchema } = makeUnionLimitOffset();
    const parsed = queryParamsSchema().parse({ limit: '10', page: '1' });
    expect(parsed.pagination.select).toEqual(['id', 'type']);
  });

  it('rejects select without discriminator field', () => {
    const { queryParamsSchema } = makeUnionLimitOffset();
    const result = queryParamsSchema().safeParse({
      select: 'id,name',
      limit: '10',
      page: '1',
    });
    expect(result.success).toBe(false);
  });

  it('validatorSchema preserves union structure (limit-offset)', () => {
    const p = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: MediaSchema,
      selectable: ['id', 'type', 'duration', 'bitrate'],
      defaultSelect: '*',
      defaultLimit: 20,
      maxLimit: 100,
    });
    const parsed = p.queryParamsSchema().parse({ limit: '10', page: '1' });
    const schema = p.validatorSchema(parsed.pagination);

    // Video item → valid
    expect(
      schema.safeParse({
        data: [{ id: 1, type: 'video', duration: 120 }],
        pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
      }).success,
    ).toBe(true);

    // Audio item → valid
    expect(
      schema.safeParse({
        data: [{ id: 2, type: 'audio', bitrate: 320 }],
        pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
      }).success,
    ).toBe(true);
  });

  it('responseSchema preserves union structure with partial per option', () => {
    const p = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: MediaSchema,
      selectable: ['id', 'type', 'duration', 'bitrate'],
      defaultSelect: '*',
      defaultLimit: 20,
      maxLimit: 100,
    });

    // Video-like partial
    expect(
      p.responseSchema.safeParse({
        data: [{ type: 'video', duration: 120 }],
        pagination: { itemsPerPage: 20, totalItems: 1, currentPage: 1, totalPages: 1 },
      }).success,
    ).toBe(true);

    // Audio-like partial
    expect(
      p.responseSchema.safeParse({
        data: [{ type: 'audio', bitrate: 320 }],
        pagination: { itemsPerPage: 20, totalItems: 1, currentPage: 1, totalPages: 1 },
      }).success,
    ).toBe(true);
  });
});

/* ------------------------------------------- */
/* Edge cases & missing branch coverage         */
/* ------------------------------------------- */

describe('paginate edge cases', () => {
  /* ---- sortBy without sortable configured ---- */

  it('rejects sortBy param when no sortable is configured', () => {
    const p = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: ModelSchema,
      selectable: ['id', 'status'],
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: '*',
    });

    const result = p.queryParamsSchema().safeParse({ sortBy: 'id:ASC', limit: '10' });
    expect(result.success).toBe(false);
  });

  /* ---- limit=0 ---- */

  it('accepts limit=0 as a valid limit', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({ limit: '0' });
    expect(parsed.pagination.limit).toBe(0);
  });

  /* ---- Default operator $eq (no $ prefix) ---- */

  it('parses filter without $ prefix as $eq', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.status': 'active',
      limit: '10',
    });
    expect(parsed.pagination.filters).toBeDefined();
  });

  /* ---- $ilike on non-string field rejected ---- */

  it('rejects $ilike operator on a number field', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const result = queryParamsSchema().safeParse({
      'filter.id': '$ilike:test',
      limit: '10',
    });
    expect(result.success).toBe(false);
  });

  /* ---- $sw on non-string field rejected ---- */

  it('rejects $sw operator on a number field', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const result = queryParamsSchema().safeParse({
      'filter.id': '$sw:test',
      limit: '10',
    });
    expect(result.success).toBe(false);
  });

  /* ---- $btw on a number field with non-parseable values rejected at runtime ---- */

  it('rejects $btw with string values on a number field', () => {
    const p = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: ModelSchema,
      selectable: ['id', 'status'],
      filterable: {
        id: { type: 'number', ops: ['$eq', '$btw'] },
      },
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id'],
    });

    // $btw calls parseNumOrDateStrict which throws for non-numeric/non-date values
    expect(() =>
      p.queryParamsSchema().parse({
        'filter.id': '$btw:a,z',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- $eq type mismatch on string field ---- */

  it('accepts $eq with string value on a string field', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.status': '$eq:active',
      limit: '10',
    });
    expect(parsed.pagination.filters).toBeDefined();
  });

  /* ---- $gt on a number field with non-parseable values rejected at runtime ---- */

  it('rejects $gt with non-parseable value on a number field', () => {
    const p = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: ModelSchema,
      selectable: ['id', 'status'],
      filterable: {
        id: { type: 'number', ops: ['$eq', '$gt'] },
      },
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id'],
    });

    // $gt calls parseNumOrDateStrict which throws for non-numeric/non-date values
    expect(() =>
      p.queryParamsSchema().parse({
        'filter.id': '$gt:abc',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- $eq on number field with non-number value ---- */

  it('rejects $eq with non-number value on a number field', () => {
    const { queryParamsSchema } = makeLimitOffset();

    // 'not-a-number' will be parsed as a string by parseSingleCondition ($eq accepts strings),
    // but validateConditionType checks the value type matches the field type
    const result = queryParamsSchema().safeParse({
      'filter.id': '$eq:not-a-number',
      limit: '10',
    });
    expect(result.success).toBe(false);
  });

  /* ---- $eq on date field with non-date value ---- */

  it('rejects $eq with non-date value on a date field', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const result = queryParamsSchema().safeParse({
      'filter.createdAt': '$eq:not-a-date',
      limit: '10',
    });
    expect(result.success).toBe(false);
  });

  /* ---- $gt on number field with non-number value ---- */

  it('rejects $gt with non-number value on a number field', () => {
    const { queryParamsSchema } = makeLimitOffset();

    // parseNumOrDateStrict throws for 'abc'
    expect(() =>
      queryParamsSchema().parse({
        'filter.id': '$gt:abc',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- $gt on date field with non-date value ---- */

  it('rejects $gt with non-date value on a date field', () => {
    const { queryParamsSchema } = makeLimitOffset();

    // parseNumOrDateStrict throws for non-date values
    expect(() =>
      queryParamsSchema().parse({
        'filter.createdAt': '$gt:not-a-date',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- $btw on number field with non-number bounds ---- */

  it('rejects $btw on number field with non-number bounds', () => {
    const p = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: ModelSchema,
      selectable: ['id', 'status'],
      filterable: {
        id: { type: 'number', ops: ['$btw'] },
      },
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id'],
    });

    // $btw calls parseNumOrDateStrict which throws for 'abc,def'
    expect(() =>
      p.queryParamsSchema().parse({
        'filter.id': '$btw:abc,def',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- $btw on date field with non-date bounds ---- */

  it('rejects $btw on date field with non-date bounds', () => {
    const { queryParamsSchema } = makeLimitOffset();

    // 'abc,def' fails parseNumOrDateStrict → throws during DSL parsing
    expect(() =>
      queryParamsSchema().parse({
        'filter.createdAt': '$btw:abc,def',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- $btw with mixed types (number and date) ---- */

  it('rejects $btw with mixed bound types', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.id': '$btw:10,2025-01-01',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- $null on any field ---- */

  it('accepts $null operator regardless of field type', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.createdAt': '$null',
      limit: '10',
    });
    expect(parsed.pagination.filters).toBeDefined();
  });

  /* ---- $not negation ---- */

  it('parses $not:$null correctly', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.createdAt': '$not:$null',
      limit: '10',
    });
    expect(parsed.pagination.filters).toBeDefined();
  });

  it('parses $not:$eq correctly', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema().parse({
      'filter.status': '$not:$eq:active',
      limit: '10',
    });
    expect(parsed.pagination.filters).toBeDefined();
  });

  /* ---- $contains operator ---- */

  it('parses $contains operator', () => {
    const p = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: ModelSchema,
      selectable: ['id', 'status'],
      filterable: {
        status: { type: 'string', ops: ['$contains'] },
      },
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id'],
    });

    const parsed = p.queryParamsSchema().parse({
      'filter.status': '$contains:a,b,c',
      limit: '10',
    });
    expect(parsed.pagination.filters).toBeDefined();
  });

  /* ---- Invalid $g: prefix (missing condition) ---- */

  it('rejects $g: prefix without a condition after the group ID', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$g:1',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- combinator without condition ---- */

  it('rejects $and without a following condition', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$g:1:$and',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- $not without operator ---- */

  it('rejects $not without an operator after it', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$not',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- group.0.join is rejected ---- */

  it('rejects group.0.join on root group', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema().parse({
        'filter.status': '$g:1:$eq:active',
        'group.0.join': '$and',
        'group.1.parent': '0',
        limit: '10',
      }),
    ).toThrow();
  });

  /* ---- group without any filters ---- */

  it('rejects group definitions without any filters', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const result = queryParamsSchema().safeParse({
      'group.1.parent': '0',
      'group.1.join': '$and',
      limit: '10',
    });
    expect(result.success).toBe(false);
  });

  /* ---- group.X without property (dotIdx === -1) silently ignored ---- */

  it('ignores malformed group keys without property', () => {
    const { queryParamsSchema } = makeLimitOffset();

    // group.1 (no .property) should be silently ignored
    const parsed = queryParamsSchema().parse({
      'filter.status': '$eq:active',
      'group.1': '$and',
      limit: '10',
    });
    expect(parsed.pagination.filters).toBeDefined();
  });

  /* ---- cursor mode ---- */

  it('CURSOR: rejects non-integer string cursor for number cursorProperty', () => {
    const { queryParamsSchema } = makeCursor();

    const result = queryParamsSchema().safeParse({
      cursor: 'not-a-number',
      limit: '10',
    });
    expect(result.success).toBe(false);
  });

  it('CURSOR: accepts valid date cursor for date cursorProperty', () => {
    const p = paginate({
      paginationType: 'CURSOR',
      dataSchema: ModelSchema,
      cursorProperty: 'createdAt',
      selectable: ['id', 'status', 'createdAt'],
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id'],
    });

    const parsed = p.queryParamsSchema().parse({
      cursor: '2025-01-15',
      limit: '10',
    });
    expect(parsed.pagination.type).toBe('CURSOR');
    expect(parsed.pagination.cursor).toBe('2025-01-15');
  });

  it('CURSOR: rejects invalid date cursor for date cursorProperty', () => {
    const p = paginate({
      paginationType: 'CURSOR',
      dataSchema: ModelSchema,
      cursorProperty: 'createdAt',
      selectable: ['id', 'status', 'createdAt'],
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id'],
    });

    const result = p.queryParamsSchema().safeParse({
      cursor: 'not-a-date',
      limit: '10',
    });
    expect(result.success).toBe(false);
  });

  it('CURSOR: accepts string cursor for string cursorProperty', () => {
    const StringModel = z.object({
      id: z.number(),
      slug: z.string(),
    });
    const p = paginate({
      paginationType: 'CURSOR',
      dataSchema: StringModel,
      cursorProperty: 'slug',
      selectable: ['id', 'slug'],
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id'],
    });

    const parsed = p.queryParamsSchema().parse({
      cursor: 'my-slug',
      limit: '10',
    });
    expect(parsed.pagination.cursor).toBe('my-slug');
  });

  it('CURSOR: validatorSchema() without args uses defaultSelect and cursor schema', () => {
    const { validatorSchema } = makeCursor();

    const schema = validatorSchema();
    expect(() =>
      schema.parse({
        data: [{ id: 1, createdAt: new Date() }],
        pagination: { itemsPerPage: 10, cursor: 42 },
      }),
    ).not.toThrow();
  });

  it('CURSOR: responseSchema uses cursor schema from cursorProperty', () => {
    const { responseSchema } = makeCursor();

    // number cursor → valid
    expect(
      responseSchema.safeParse({
        data: [],
        pagination: { itemsPerPage: 10, cursor: 42 },
      }).success,
    ).toBe(true);

    // string cursor → rejected (cursorProperty is z.number)
    expect(
      responseSchema.safeParse({
        data: [],
        pagination: { itemsPerPage: 10, cursor: 'abc' },
      }).success,
    ).toBe(false);
  });

  /* ---- Nested discriminated unions in paginate ---- */

  it('paginate rejects select without discriminator on top-level discriminated union', () => {
    const MediaSchema = z.discriminatedUnion('type', [
      z.object({ type: z.literal('audio'), id: z.number(), bitrate: z.number() }),
      z.object({ type: z.literal('video'), id: z.number(), duration: z.number() }),
    ]);

    const p = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: MediaSchema,
      selectable: ['id', 'type'],
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id', 'type'],
    });

    // id without type → rejected (discriminator required)
    const result = p.queryParamsSchema().safeParse({
      select: 'id',
      limit: '10',
    });
    expect(result.success).toBe(false);

    // id with type → accepted
    const parsed = p.queryParamsSchema().parse({
      select: 'id,type',
      limit: '10',
    });
    expect(parsed.pagination.select).toContain('type');
  });

  /* ---- queryParamsSchema with extra shape ---- */

  it('queryParamsSchema(extra): parses extra fields alongside pagination', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const extended = queryParamsSchema({
      search: z.string().optional(),
    });

    const parsed = extended.parse({ limit: '10', page: '1', search: 'alice' });
    expect(parsed.pagination.limit).toBe(10);
    expect(parsed.search).toBe('alice');
  });

  it('queryParamsSchema(extra): collects errors from both pagination and extra fields', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const extended = queryParamsSchema({
      search: z.string().min(3),
    });

    expect(() =>
      extended.parse({
        limit: '999',
        search: 'ab',
      }),
    ).toThrow();
  });

  /* ---- Malformed date that passes regex but fails Date.parse ---- */

  it('rejects dates that match ISO regex but fail Date.parse', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const result = queryParamsSchema().safeParse({
      'filter.createdAt': '$eq:9999-99-99',
      limit: '10',
    });
    expect(result.success).toBe(false);
  });

  /* ---- all valid operators accepted for a number field ---- */

  it('accepts all valid operators on a number field', () => {
    const p = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: ModelSchema,
      selectable: ['id', 'status'],
      filterable: {
        id: { type: 'number', ops: ['$eq', '$gt', '$btw'] },
      },
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id'],
    });

    // $eq with number
    const parsed = p.queryParamsSchema().parse({
      'filter.id': '$eq:42',
      limit: '10',
    });
    expect(parsed.pagination.filters).toBeDefined();

    // $gt with number
    const parsed2 = p.queryParamsSchema().parse({
      'filter.id': '$gt:10',
      limit: '10',
    });
    expect(parsed2.pagination.filters).toBeDefined();

    // $btw with numbers
    const parsed3 = p.queryParamsSchema().parse({
      'filter.id': '$btw:1,100',
      limit: '10',
    });
    expect(parsed3.pagination.filters).toBeDefined();
  });

  /* ---- Cursor with wrapped schema (optional/nullable/default) ---- */

  it('CURSOR: handles optional-wrapped cursorProperty schema', () => {
    const WrappedModel = z.object({
      id: z.number().optional(),
      name: z.string(),
    });

    const p = paginate({
      paginationType: 'CURSOR',
      dataSchema: WrappedModel,
      cursorProperty: 'id',
      selectable: ['id', 'name'],
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id'],
    });

    const parsed = p.queryParamsSchema().parse({ cursor: '42', limit: '10' });
    expect(parsed.pagination.cursor).toBe(42);
  });
});
