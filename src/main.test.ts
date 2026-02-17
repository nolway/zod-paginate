import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { paginate, PaginationQueryParams } from './main';

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

function makeLimitOffset(): {
  queryParamsSchema: z.ZodType<PaginationQueryParams<typeof ModelSchema>>;
  validatorSchema: (parsed?: PaginationQueryParams<typeof ModelSchema>) => z.ZodType;
} {
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
    defaultSelect: ['*'],
  });
}

function makeCursor(): {
  queryParamsSchema: z.ZodType<PaginationQueryParams<typeof ModelSchema>>;
  validatorSchema: (parsed?: PaginationQueryParams<typeof ModelSchema>) => z.ZodType;
} {
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

    const parsed = queryParamsSchema.parse({
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

    const parsed = queryParamsSchema.parse({
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
      queryParamsSchema.parse({
        limit: '999',
        page: '1',
      }),
    ).toThrow();
  });

  it('normalizes sortBy: string -> array, and parses SortItem', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
      sortBy: 'createdAt:DESC',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.sortBy).toEqual([{ property: 'createdAt', direction: 'DESC' }]);
    }
  });

  it('normalizes sortBy: string[] stays array and parses multiple items', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
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

    const parsed = queryParamsSchema.parse({
      sortBy: ['  ', 'createdAt:DESC'],
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.sortBy).toEqual([{ property: 'createdAt', direction: 'DESC' }]);
    }
  });

  it('sortBy with only empty values falls back to defaultSortBy', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
      sortBy: ['   ', ' '],
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.sortBy).toEqual([{ property: 'createdAt', direction: 'DESC' }]);
    }
  });

  it('applies defaultSortBy when sortBy is missing', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
      page: '1',
      limit: '10',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.sortBy).toEqual([{ property: 'createdAt', direction: 'DESC' }]);
    }
  });

  it('parses select CSV and enforces selectable allowlist', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
      select: 'id,status',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.select).toEqual(['id', 'status']);
    }

    expect(() =>
      queryParamsSchema.parse({
        select: 'id,unknownField',
      }),
    ).toThrow();
  });

  it('expands select="*" using selectable + uses defaultSelect when missing', () => {
    const { queryParamsSchema } = makeLimitOffset();

    // Missing select -> defaultSelect ["*"] -> expand to selectable list
    const parsed = queryParamsSchema.parse({
      limit: '10',
      page: '1',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed.pagination.select).toEqual(['id', 'status', 'createdAt', 'meta.score']);
    }

    // Explicit "*"
    const parsed2 = queryParamsSchema.parse({
      select: '*',
    });

    expect(parsed2.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed2.pagination.type === 'LIMIT_OFFSET') {
      expect(parsed2.pagination.select).toEqual(['id', 'status', 'createdAt', 'meta.score']);
    }
  });

  it('normalizes filter.<field> string -> string[] and builds filters AST', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
      'filter.status': '$eq:active',
      'filter.id': '$gt:10',
    });

    expect(parsed.pagination.filters).toBeTruthy();
    expect(parsed.pagination.filters.type).toBeDefined();
  });

  it('supports $not as prefix: $not:$null', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
      'filter.createdAt': '$not:$null',
    });

    const root = parsed.pagination.filters;

    const collect = (n: typeof root): { field: string; not?: boolean; op: string }[] => {
      if (n.type === 'filter')
        return [{ field: n.field, not: n.condition.not, op: n.condition.op }];
      return n.items.flatMap(collect);
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
      queryParamsSchema.parse({
        'filter.unknown': '$eq:test',
      }),
    ).toThrow();
  });

  it('rejects operators not allowed for a field (runtime)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.status': '$gt:10',
      }),
    ).toThrow();
  });

  it('rejects type mismatch on comparable ops: date field with number bounds vs ISO date', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.createdAt': '$gt:123',
      }),
    ).toThrow();

    expect(() =>
      queryParamsSchema.parse({
        'filter.id': '$gt:2022-01-01',
      }),
    ).toThrow();
  });

  it('rejects $btw when bounds are not same kind (number vs date)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.createdAt': '$btw:2022-01-01,10',
      }),
    ).toThrow();
  });

  it('supports $btw for date fields when ISO bounds are valid', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
      'filter.createdAt': '$btw:2022-01-01,2022-01-10',
    });

    expect(parsed.pagination.filters).toBeTruthy();
  });

  it('supports $in for number fields (value is array of strings in DSL)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
      'filter.id': '$in:1,2,3',
    });

    const root = parsed.pagination.filters;

    const collectOps = (n: typeof root): string[] => {
      if (n.type === 'filter') return [n.condition.op];
      return n.items.flatMap(collectOps);
    };

    expect(collectOps(root)).toContain('$in');
  });

  it('supports groups via $g:<id> and group.<id>.* definitions', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
      'filter.status': ['$g:1:$eq:active', '$g:1:$or:$eq:postponed'],
      'filter.createdAt': ['$g:2:$not:$null', '$g:2:$and:$btw:2022-01-01,2022-02-01'],

      'group.1.parent': '0',
      'group.2.parent': '0',
      'group.2.join': '$and',
    });

    expect(parsed.pagination.filters).toBeTruthy();
    expect(parsed.pagination.filters.type).toBe('and');
  });

  it('rejects invalid group defs: group.0.parent is forbidden', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.status': '$eq:active',
        'group.0.parent': '1',
      }),
    ).toThrow();
  });

  it('LIMIT_OFFSET: rejects cursor param', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        cursor: 'abc',
      }),
    ).toThrow();
  });

  it('CURSOR pagination: rejects page and includes cursorProperty in output', () => {
    const { queryParamsSchema } = makeCursor();

    expect(() =>
      queryParamsSchema.parse({
        page: '1',
        cursor: '123',
      }),
    ).toThrow();

    const parsed = queryParamsSchema.parse({
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

    const parsed = queryParamsSchema.parse({
      cursor: '123',
    });

    expect(parsed.pagination.type).toBe('CURSOR');
    if (parsed.pagination.type === 'CURSOR') {
      expect(parsed.pagination.limit).toBe(10);
    }
  });

  it('select empty CSV (select=) is rejected', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        select: '',
      }),
    ).toThrow();
  });

  it('sortBy invalid direction is rejected', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        sortBy: 'createdAt:DOWN',
      }),
    ).toThrow();
  });

  it('filter invalid operator is rejected', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.status': '$wat:active',
      }),
    ).toThrow();
  });

  it('rejects first condition in a group having a combinator ($or / $and)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.status': ['$g:1:$or:$eq:active'],
      }),
    ).toThrow();
  });

  it('rejects first child group having a join operator', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.status': '$g:1:$eq:active',
        'group.1.parent': '0',
        'group.1.join': '$and',
      }),
    ).toThrow();
  });

  it('rejects cyclic group definitions', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.status': '$g:1:$eq:active',
        'group.1.parent': '2',
        'group.2.parent': '1',
      }),
    ).toThrow();
  });

  it('resolves sibling groups in numeric order (deterministic folding)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
      'filter.status': ['$g:2:$eq:active'],
      'filter.id': ['$g:10:$eq:1'],

      'group.2.parent': '0',
      'group.10.parent': '0',
      'group.10.join': '$or',
    });

    const root = parsed.pagination.filters;

    expect(root.type).toBe('or');
  });

  it('rejects invalid $btw format (missing bound)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.createdAt': '$btw:2022-01-01',
      }),
    ).toThrow();
  });

  it('rejects invalid $not usage without operator', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.status': '$not:',
      }),
    ).toThrow();
  });

  it('supports nested group tree', () => {
    const { queryParamsSchema } = makeLimitOffset();

    const parsed = queryParamsSchema.parse({
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
    expect(root.type).toBe('and');
  });

  it('rejects unknown group id format (non-integer)', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
        'filter.status': '$g:abc:$eq:active',
      }),
    ).toThrow();
  });

  it('rejects invalid group join value', () => {
    const { queryParamsSchema } = makeLimitOffset();

    expect(() =>
      queryParamsSchema.parse({
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
    const parsed = queryParamsSchema.parse({ page: '1', limit: '10' });

    const v = validatorSchema(parsed);

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

    const parsed = queryParamsSchema.parse({
      select: 'id,status',
      page: '1',
      limit: '10',
    });

    const v = validatorSchema(parsed);

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

    const parsed = queryParamsSchema.parse({
      cursor: '123',
    });

    const v = validatorSchema(parsed);

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

    const parsed = queryParamsSchema.parse({
      cursor: '123',
      select: 'id,status',
    });

    const v = validatorSchema(parsed);

    // should require id + status
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

    const parsed = queryParamsSchema.parse({
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
});
