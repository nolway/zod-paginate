import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { paginate, select, type WhereNode } from './main';

/* ========================================================================= */
/*  Shared schemas                                                           */
/* ========================================================================= */

const UserSchema = z.object({
  id: z.number(),
  username: z.string(),
  email: z.string(),
  role: z.string(),
  age: z.number(),
  createdAt: z.date(),
  profile: z.object({
    bio: z.string(),
    avatar: z.string(),
    settings: z.object({
      theme: z.string(),
    }),
  }),
});

const ArticleSchema = z.object({
  id: z.number(),
  title: z.string(),
  slug: z.string(),
  status: z.string(),
  publishedAt: z.date(),
  author: z.object({
    name: z.string(),
    id: z.number(),
  }),
  stats: z.object({
    views: z.number(),
    likes: z.number(),
  }),
});

/* ========================================================================= */
/*  Helpers                                                                  */
/* ========================================================================= */

/** Collect all leaf filter nodes from a WhereNode tree. */
function collectLeaves(
  node: WhereNode | undefined,
): { field: string; op: string; not?: boolean }[] {
  if (!node) return [];
  if (node.type === 'filter') {
    return [{ field: node.field, op: node.condition.op, not: node.condition.not }];
  }
  return node.items.flatMap(collectLeaves);
}

/* ========================================================================= */
/*  LIMIT_OFFSET — Full flow                                                 */
/* ========================================================================= */

describe('Integration: LIMIT_OFFSET full flow', () => {
  function setup(): ReturnType<typeof paginate> {
    return paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: UserSchema,
      selectable: [
        'id',
        'username',
        'email',
        'role',
        'age',
        'createdAt',
        'profile.bio',
        'profile.avatar',
        'profile.settings.theme',
      ],
      sortable: ['createdAt', 'id', 'username', 'age'],
      filterable: {
        role: { type: 'string', ops: ['$eq', '$in', '$ilike'] },
        age: { type: 'number', ops: ['$gt', '$gte', '$lt', '$lte', '$btw', '$eq'] },
        createdAt: { type: 'date', ops: ['$btw', '$gt', '$lte', '$null'] },
        username: { type: 'string', ops: ['$eq', '$ilike', '$sw'] },
        email: { type: 'string', ops: ['$eq', '$contains'] },
      },
      defaultSortBy: [{ property: 'createdAt', direction: 'DESC' }],
      defaultLimit: 25,
      maxLimit: 100,
      defaultSelect: '*',
    });
  }

  it('parses a complex query combining select, sort, filters, and pagination', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({
      limit: '15',
      page: '3',
      select: 'id,username,email,age',
      sortBy: ['age:ASC', 'username:DESC'],
      'filter.role': '$in:admin,editor',
      'filter.age': ['$gte:18', '$and:$lte:65'],
      'filter.createdAt': '$gt:2024-01-01',
    });

    expect(parsed.pagination.type).toBe('LIMIT_OFFSET');
    if (parsed.pagination.type !== 'LIMIT_OFFSET') return;

    expect(parsed.pagination.limit).toBe(15);
    expect(parsed.pagination.page).toBe(3);
    expect(parsed.pagination.select).toEqual(['id', 'username', 'email', 'age']);
    expect(parsed.pagination.sortBy).toEqual([
      { property: 'age', direction: 'ASC' },
      { property: 'username', direction: 'DESC' },
    ]);

    const leaves = collectLeaves(parsed.pagination.filters);
    expect(leaves).toHaveLength(4);
    expect(leaves.map((l) => l.op)).toEqual(expect.arrayContaining(['$in', '$gte', '$lte', '$gt']));
  });

  it('validates response shape after parsing with explicit select', () => {
    const { queryParamsSchema, validatorSchema } = setup();

    const parsed = queryParamsSchema.parse({
      select: 'id,username,profile.bio',
      limit: '10',
      page: '1',
    });

    const v = validatorSchema(parsed.pagination);

    // Valid response
    expect(() =>
      v.parse({
        data: [
          { id: 1, username: 'alice', profile: { bio: 'Hello' } },
          { id: 2, username: 'bob', profile: { bio: 'World' } },
        ],
        pagination: {
          itemsPerPage: 10,
          totalItems: 2,
          currentPage: 1,
          totalPages: 1,
        },
      }),
    ).not.toThrow();

    // Missing projected field => invalid
    expect(() =>
      v.parse({
        data: [{ id: 1, username: 'alice' }],
        pagination: {
          itemsPerPage: 10,
          totalItems: 1,
          currentPage: 1,
          totalPages: 1,
        },
      }),
    ).toThrow();
  });

  it('validates response with deeply nested select projection', () => {
    const { queryParamsSchema, validatorSchema } = setup();

    const parsed = queryParamsSchema.parse({
      select: 'id,profile.settings.theme',
      limit: '5',
      page: '1',
    });

    const v = validatorSchema(parsed.pagination);

    expect(() =>
      v.parse({
        data: [{ id: 1, profile: { settings: { theme: 'dark' } } }],
        pagination: { itemsPerPage: 5, totalItems: 1, currentPage: 1, totalPages: 1 },
      }),
    ).not.toThrow();

    // Missing nested field
    expect(() =>
      v.parse({
        data: [{ id: 1, profile: {} }],
        pagination: { itemsPerPage: 5, totalItems: 1, currentPage: 1, totalPages: 1 },
      }),
    ).toThrow();
  });

  it('filters with groups build correct AST structure', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({
      // Group 1: role = admin OR role = editor
      'filter.role': ['$g:1:$eq:admin', '$g:1:$or:$eq:editor'],
      // Group 2: age >= 18 AND age <= 65
      'filter.age': ['$g:2:$gte:18', '$g:2:$and:$lte:65'],

      'group.1.parent': '0',
      'group.2.parent': '0',
      'group.2.join': '$and',
    });

    const root = parsed.pagination.filters;
    expect(root).toBeTruthy();

    // Root should be AND (group 1 AND group 2)
    expect(root?.type).toBe('and');

    const leaves = collectLeaves(root);
    expect(leaves).toHaveLength(4);
  });

  it('filters with $not operator negate conditions correctly', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({
      'filter.createdAt': '$not:$null',
      'filter.username': '$not:$ilike:test',
    });

    const leaves = collectLeaves(parsed.pagination.filters);
    expect(leaves).toHaveLength(2);

    const createdAt = leaves.find((l) => l.field === 'createdAt');
    expect(createdAt?.not).toBe(true);
    expect(createdAt?.op).toBe('$null');

    const username = leaves.find((l) => l.field === 'username');
    expect(username?.not).toBe(true);
    expect(username?.op).toBe('$ilike');
  });

  it('defaults are applied when optional params are omitted', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({});

    if (parsed.pagination.type !== 'LIMIT_OFFSET') return;

    expect(parsed.pagination.limit).toBe(25); // defaultLimit
    expect(parsed.pagination.sortBy).toEqual([{ property: 'createdAt', direction: 'DESC' }]); // defaultSortBy
    expect(parsed.pagination.select).toEqual([
      'id',
      'username',
      'email',
      'role',
      'age',
      'createdAt',
      'profile.bio',
      'profile.avatar',
      'profile.settings.theme',
    ]); // defaultSelect: ["*"]
    expect(parsed.pagination.page).toBeUndefined();
    expect(parsed.pagination.filters).toBeUndefined();
  });

  it('end-to-end: parse query → validate response with all features combined', () => {
    const { queryParamsSchema, validatorSchema } = setup();

    const parsed = queryParamsSchema.parse({
      limit: '10',
      page: '1',
      select: 'id,username,age,role',
      sortBy: 'age:ASC',
      'filter.role': '$eq:admin',
      'filter.age': '$gte:21',
    });

    const v = validatorSchema(parsed.pagination);

    const validResponse = {
      data: [
        { id: 1, username: 'alice', age: 30, role: 'admin' },
        { id: 2, username: 'bob', age: 25, role: 'admin' },
      ],
      pagination: {
        itemsPerPage: 10,
        totalItems: 2,
        currentPage: 1,
        totalPages: 1,
        sortBy: [{ property: 'age', direction: 'ASC' }],
      },
    };

    expect(() => v.parse(validResponse)).not.toThrow();
  });

  it('rejects combined invalid params in a single query', () => {
    const { queryParamsSchema } = setup();

    // Invalid: limit exceeds maxLimit + unknown filter field + bad sort direction
    expect(() =>
      queryParamsSchema.parse({
        limit: '999',
        'filter.unknown': '$eq:test',
        sortBy: 'id:SIDEWAYS',
      }),
    ).toThrow();
  });

  it('handles $btw with date ranges and validates type consistency', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({
      'filter.createdAt': '$btw:2024-01-01,2024-12-31',
    });

    const leaves = collectLeaves(parsed.pagination.filters);
    expect(leaves).toHaveLength(1);
    expect(leaves[0]?.op).toBe('$btw');

    // Reject mixed types in $btw (number + date)
    expect(() =>
      queryParamsSchema.parse({
        'filter.createdAt': '$btw:2024-01-01,42',
      }),
    ).toThrow();
  });

  it('handles $btw with number ranges', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({
      'filter.age': '$btw:18,99',
    });

    const leaves = collectLeaves(parsed.pagination.filters);
    expect(leaves).toHaveLength(1);
    expect(leaves[0]?.op).toBe('$btw');
  });

  it('handles $sw (starts-with) and $ilike on string fields', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({
      'filter.username': ['$sw:al', '$or:$ilike:bob'],
    });

    const leaves = collectLeaves(parsed.pagination.filters);
    expect(leaves).toHaveLength(2);
    expect(leaves.map((l) => l.op)).toEqual(expect.arrayContaining(['$sw', '$ilike']));
  });

  it('handles $contains on string array fields', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({
      'filter.email': '$contains:example.com,test.org',
    });

    const leaves = collectLeaves(parsed.pagination.filters);
    expect(leaves).toHaveLength(1);
    expect(leaves[0]?.op).toBe('$contains');
  });

  it('handles sortBy with property not in sortable list (silently dropped)', () => {
    const { queryParamsSchema } = setup();

    // email is not in sortable: only the valid sort item is kept
    const parsed = queryParamsSchema.parse({
      sortBy: ['createdAt:ASC', 'email:DESC'],
    });

    if (parsed.pagination.type !== 'LIMIT_OFFSET') return;

    expect(parsed.pagination.sortBy).toEqual([{ property: 'createdAt', direction: 'ASC' }]);

    // If *all* sort items are unknown, sortBy resolves to undefined (no fallback to default)
    const parsed2 = queryParamsSchema.parse({
      sortBy: 'email:DESC',
    });

    if (parsed2.pagination.type !== 'LIMIT_OFFSET') return;

    expect(parsed2.pagination.sortBy).toBeUndefined();
  });
});

/* ========================================================================= */
/*  CURSOR — Full flow                                                       */
/* ========================================================================= */

describe('Integration: CURSOR full flow', () => {
  function setup(): ReturnType<typeof paginate> {
    return paginate({
      paginationType: 'CURSOR',
      dataSchema: ArticleSchema,
      cursorProperty: 'id',
      selectable: [
        'id',
        'title',
        'slug',
        'status',
        'publishedAt',
        'author.name',
        'author.id',
        'stats.views',
        'stats.likes',
      ],
      sortable: ['publishedAt', 'id', 'stats.views'],
      filterable: {
        status: { type: 'string', ops: ['$eq', '$in'] },
        'author.name': { type: 'string', ops: ['$eq', '$ilike'] },
        publishedAt: { type: 'date', ops: ['$btw', '$gt', '$lte', '$null'] },
        'stats.views': { type: 'number', ops: ['$gte', '$lte'] },
        'stats.likes': { type: 'number', ops: ['$gt'] },
      },
      defaultLimit: 20,
      maxLimit: 50,
      defaultSelect: ['id', 'title', 'status'],
    });
  }

  it('parses cursor-based query with all features', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({
      cursor: '42',
      limit: '10',
      select: 'id,title,status,author.name,stats.views',
      sortBy: 'publishedAt:DESC',
      'filter.status': '$eq:published',
      'filter.stats.views': '$gte:100',
    });

    expect(parsed.pagination.type).toBe('CURSOR');
    if (parsed.pagination.type !== 'CURSOR') return;

    expect(parsed.pagination.cursor).toBe(42); // coerced to number
    expect(parsed.pagination.limit).toBe(10);
    expect(parsed.pagination.cursorProperty).toBe('id');
    expect(parsed.pagination.select).toEqual([
      'id',
      'title',
      'status',
      'author.name',
      'stats.views',
    ]);
    expect(parsed.pagination.sortBy).toEqual([{ property: 'publishedAt', direction: 'DESC' }]);

    const leaves = collectLeaves(parsed.pagination.filters);
    expect(leaves).toHaveLength(2);
  });

  it('validates response shape with cursor pagination metadata', () => {
    const { queryParamsSchema, validatorSchema } = setup();

    const parsed = queryParamsSchema.parse({
      cursor: '10',
      select: 'id,title,author.name',
    });

    const v = validatorSchema(parsed.pagination);

    // Valid
    expect(() =>
      v.parse({
        data: [
          { id: 11, title: 'Hello World', author: { name: 'Alice' } },
          { id: 12, title: 'Foo Bar', author: { name: 'Bob' } },
        ],
        pagination: {
          itemsPerPage: 20,
          cursor: 12,
        },
      }),
    ).not.toThrow();

    // Invalid: cursor should be a number (id field is z.number())
    expect(() =>
      v.parse({
        data: [{ id: 11, title: 'Hello World', author: { name: 'Alice' } }],
        pagination: {
          itemsPerPage: 20,
          cursor: 'not-a-number',
        },
      }),
    ).toThrow();
  });

  it('applies defaults when no params are provided', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({});

    if (parsed.pagination.type !== 'CURSOR') return;

    expect(parsed.pagination.limit).toBe(20); // defaultLimit
    expect(parsed.pagination.cursor).toBeUndefined();
    expect(parsed.pagination.select).toEqual(['id', 'title', 'status']); // defaultSelect
    expect(parsed.pagination.filters).toBeUndefined();
  });

  it('rejects page param in cursor mode', () => {
    const { queryParamsSchema } = setup();

    expect(() =>
      queryParamsSchema.parse({
        page: '1',
      }),
    ).toThrow();
  });

  it('rejects non-integer cursor for a number field', () => {
    const { queryParamsSchema } = setup();

    expect(() =>
      queryParamsSchema.parse({
        cursor: 'abc',
      }),
    ).toThrow();
  });

  it('end-to-end: parse query → validate full response with nested select', () => {
    const { queryParamsSchema, validatorSchema } = setup();

    const parsed = queryParamsSchema.parse({
      cursor: '100',
      limit: '5',
      select: 'id,title,stats.views,stats.likes,author.name',
      sortBy: ['stats.views:DESC', 'id:ASC'],
      'filter.status': '$in:published,featured',
      'filter.stats.views': '$gte:50',
    });

    const v = validatorSchema(parsed.pagination);

    // Valid response
    expect(() =>
      v.parse({
        data: [
          {
            id: 101,
            title: 'Popular',
            stats: { views: 500, likes: 100 },
            author: { name: 'Alice' },
          },
          { id: 102, title: 'Trending', stats: { views: 300, likes: 50 }, author: { name: 'Bob' } },
        ],
        pagination: {
          itemsPerPage: 5,
          cursor: 102,
        },
      }),
    ).not.toThrow();

    // Invalid: missing stats.likes (projected)
    expect(() =>
      v.parse({
        data: [{ id: 101, title: 'Popular', stats: { views: 500 }, author: { name: 'Alice' } }],
        pagination: {
          itemsPerPage: 5,
          cursor: 101,
        },
      }),
    ).toThrow();
  });

  it('handles complex grouped filters in cursor mode', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({
      cursor: '50',
      // Group 1: status published OR featured
      'filter.status': ['$g:1:$eq:published', '$g:1:$or:$eq:featured'],
      // Group 2: views >= 100 AND views <= 10000
      'filter.stats.views': ['$g:2:$gte:100', '$g:2:$and:$lte:10000'],

      'group.1.parent': '0',
      'group.2.parent': '0',
      'group.2.join': '$and',
    });

    const root = parsed.pagination.filters;
    expect(root).toBeTruthy();
    expect(root?.type).toBe('and');

    const leaves = collectLeaves(root);
    expect(leaves).toHaveLength(4);
  });
});

/* ========================================================================= */
/*  CURSOR with date cursor property                                         */
/* ========================================================================= */

describe('Integration: CURSOR with date cursorProperty', () => {
  const EventSchema = z.object({
    id: z.number(),
    name: z.string(),
    occurredAt: z.date(),
    severity: z.string(),
  });

  function setup(): ReturnType<typeof paginate> {
    return paginate({
      paginationType: 'CURSOR',
      dataSchema: EventSchema,
      cursorProperty: 'occurredAt',
      selectable: ['id', 'name', 'occurredAt', 'severity'],
      sortable: ['occurredAt', 'id'],
      filterable: {
        severity: { type: 'string', ops: ['$eq'] },
      },
      defaultLimit: 50,
      maxLimit: 200,
      defaultSelect: ['id', 'name', 'occurredAt'],
    });
  }

  it('coerces ISO date cursor string correctly', () => {
    const { queryParamsSchema } = setup();

    const parsed = queryParamsSchema.parse({
      cursor: '2025-06-15T12:00:00Z',
      limit: '10',
    });

    if (parsed.pagination.type !== 'CURSOR') return;

    expect(parsed.pagination.cursor).toBe('2025-06-15T12:00:00Z');
    expect(typeof parsed.pagination.cursor).toBe('string');
  });

  it('rejects non-ISO cursor for date cursorProperty', () => {
    const { queryParamsSchema } = setup();

    expect(() =>
      queryParamsSchema.parse({
        cursor: 'not-a-date',
      }),
    ).toThrow();
  });

  it('validates response cursor type matches date expectation', () => {
    const { queryParamsSchema, validatorSchema } = setup();

    const parsed = queryParamsSchema.parse({
      cursor: '2025-01-01T00:00:00Z',
    });

    const v = validatorSchema(parsed.pagination);

    // cursor as ISO string
    expect(() =>
      v.parse({
        data: [{ id: 1, name: 'evt', occurredAt: new Date() }],
        pagination: { itemsPerPage: 50, cursor: '2025-01-02T00:00:00Z' },
      }),
    ).not.toThrow();

    // cursor as Date object (also valid per schema)
    expect(() =>
      v.parse({
        data: [{ id: 1, name: 'evt', occurredAt: new Date() }],
        pagination: { itemsPerPage: 50, cursor: new Date('2025-01-02') },
      }),
    ).not.toThrow();
  });
});

/* ========================================================================= */
/*  select() standalone — Full flow                                          */
/* ========================================================================= */

describe('Integration: select() full flow', () => {
  // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
  function setup() {
    return select({
      dataSchema: UserSchema,
      selectable: [
        'id',
        'username',
        'email',
        'role',
        'age',
        'profile.bio',
        'profile.avatar',
        'profile.settings.theme',
      ],
      defaultSelect: ['id', 'username', 'email'],
    });
  }

  it('parses select and validates response in one flow', () => {
    const { queryParamsSchema, validatorSchema } = setup();

    const parsed = queryParamsSchema.parse({ select: 'id,username,profile.settings.theme' });
    const v = validatorSchema(parsed);

    expect(() =>
      v.parse({
        data: [{ id: 1, username: 'alice', profile: { settings: { theme: 'dark' } } }],
      }),
    ).not.toThrow();

    // Missing nested projection
    expect(() =>
      v.parse({
        data: [{ id: 1, username: 'alice' }],
      }),
    ).toThrow();
  });

  it('uses defaultSelect when no select provided and validates accordingly', () => {
    const { queryParamsSchema, validatorSchema } = setup();

    const parsed = queryParamsSchema.parse({});
    expect(parsed.select).toEqual(['id', 'username', 'email']);

    const v = validatorSchema(parsed);

    expect(() =>
      v.parse({
        data: [{ id: 1, username: 'alice', email: 'alice@example.com' }],
      }),
    ).not.toThrow();

    // email missing => invalid
    expect(() =>
      v.parse({
        data: [{ id: 1, username: 'alice' }],
      }),
    ).toThrow();
  });

  it('wildcard expansion works end-to-end', () => {
    const { queryParamsSchema, validatorSchema } = select({
      dataSchema: UserSchema,
      selectable: [
        'id',
        'username',
        'email',
        'role',
        'age',
        'profile.bio',
        'profile.avatar',
        'profile.settings.theme',
      ],
      defaultSelect: '*',
    });

    const parsed = queryParamsSchema.parse({});
    expect(parsed.select).toEqual([
      'id',
      'username',
      'email',
      'role',
      'age',
      'profile.bio',
      'profile.avatar',
      'profile.settings.theme',
    ]);

    const v = validatorSchema(parsed);

    expect(() =>
      v.parse({
        data: [
          {
            id: 1,
            username: 'alice',
            email: 'a@b.com',
            role: 'admin',
            age: 30,
            profile: { bio: 'Hi', avatar: 'url', settings: { theme: 'light' } },
          },
        ],
      }),
    ).not.toThrow();
  });

  it('validates empty array is always valid', () => {
    const { queryParamsSchema, validatorSchema } = setup();
    const parsed = queryParamsSchema.parse({});
    const v = validatorSchema(parsed);

    expect(() => v.parse({ data: [] })).not.toThrow();
  });

  it('responseSchema: validates without parsing query params', () => {
    const { responseSchema } = setup();

    // defaultSelect: ['id', 'username', 'email']
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, username: 'alice', email: 'alice@example.com' }],
      }),
    ).not.toThrow();

    // Missing email => invalid
    expect(() =>
      responseSchema.parse({
        data: [{ id: 1, username: 'alice' }],
      }),
    ).toThrow();
  });
});

/* ========================================================================= */
/*  Edge cases & cross-feature interactions                                  */
/* ========================================================================= */

describe('Integration: Edge cases', () => {
  it('paginate with minimal config applies defaults', () => {
    const MinimalSchema = z.object({
      id: z.number(),
      name: z.string(),
    });

    const { queryParamsSchema, validatorSchema } = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: MinimalSchema,
      selectable: ['id', 'name'],
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: ['id', 'name'],
    });

    // Should parse with no params
    const parsed = queryParamsSchema.parse({});

    expect(parsed.pagination.limit).toBe(10);
    expect(parsed.pagination.sortBy).toBeUndefined();
    expect(parsed.pagination.select).toEqual(['id', 'name']);
    expect(parsed.pagination.filters).toBeUndefined();

    // Validator uses defaultSelect projection
    const v = validatorSchema(parsed.pagination);
    expect(() =>
      v.parse({
        data: [{ id: 1, name: 'test' }],
        pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
      }),
    ).not.toThrow();
  });

  it('multiple filter conditions on same field with different operators', () => {
    const { queryParamsSchema } = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: UserSchema,
      selectable: ['id', 'username', 'age'],
      defaultLimit: 20,
      maxLimit: 100,
      defaultSelect: ['id', 'username', 'age'],
      filterable: {
        age: { type: 'number', ops: ['$gte', '$lte', '$eq'] },
      },
    });

    const parsed = queryParamsSchema.parse({
      'filter.age': ['$gte:18', '$and:$lte:65'],
    });

    const leaves = collectLeaves(parsed.pagination.filters);
    expect(leaves).toHaveLength(2);
    expect(leaves.map((l) => l.op)).toEqual(['$gte', '$lte']);
  });

  it('filter $eq with plain string value (no operator prefix)', () => {
    const { queryParamsSchema } = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: UserSchema,
      selectable: ['id', 'username', 'role'],
      defaultLimit: 20,
      maxLimit: 100,
      defaultSelect: ['id', 'username', 'role'],
      filterable: {
        role: { type: 'string', ops: ['$eq'] },
      },
    });

    // Plain value without $op: prefix should be treated as $eq
    const parsed = queryParamsSchema.parse({
      'filter.role': 'admin',
    });

    const leaves = collectLeaves(parsed.pagination.filters);
    expect(leaves).toHaveLength(1);
    expect(leaves[0]?.op).toBe('$eq');
  });

  it('multiple groups with nested parent relationships', () => {
    const { queryParamsSchema } = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: UserSchema,
      selectable: ['id', 'username', 'role', 'age'],
      defaultLimit: 20,
      maxLimit: 100,
      defaultSelect: ['id', 'username', 'role', 'age'],
      filterable: {
        role: { type: 'string', ops: ['$eq'] },
        age: { type: 'number', ops: ['$gte', '$lte'] },
        username: { type: 'string', ops: ['$ilike'] },
      },
    });

    const parsed = queryParamsSchema.parse({
      // Group 1: role = admin
      'filter.role': '$g:1:$eq:admin',
      // Group 2: age 18..65 (child of group 1)
      'filter.age': ['$g:2:$gte:18', '$g:2:$and:$lte:65'],
      // Group 3: username contains "test" (child of group 1, joined with OR to group 2)
      'filter.username': '$g:3:$ilike:test',

      'group.1.parent': '0',
      'group.1.op': '$and',

      'group.2.parent': '1',
      'group.3.parent': '1',
      'group.3.join': '$or',
    });

    const root = parsed.pagination.filters;
    expect(root).toBeTruthy();

    // Should have all 4 leaf conditions
    const leaves = collectLeaves(root);
    expect(leaves).toHaveLength(4);
  });

  it('validator without parsed params uses defaults', () => {
    const { validatorSchema } = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: ArticleSchema,
      selectable: ['id', 'title'],
      defaultLimit: 20,
      maxLimit: 100,
      defaultSelect: ['id', 'title'],
    });

    const v = validatorSchema(); // no parsed params

    expect(() =>
      v.parse({
        data: [{ id: 1, title: 'Hello' }],
        pagination: { itemsPerPage: 10, totalItems: 1, currentPage: 1, totalPages: 1 },
      }),
    ).not.toThrow();
  });

  it('CURSOR with string cursorProperty', () => {
    const SlugSchema = z.object({
      slug: z.string(),
      title: z.string(),
    });

    const { queryParamsSchema, validatorSchema } = paginate({
      paginationType: 'CURSOR',
      dataSchema: SlugSchema,
      cursorProperty: 'slug',
      selectable: ['slug', 'title'],
      defaultSelect: ['slug', 'title'],
      defaultLimit: 10,
      maxLimit: 50,
    });

    const parsed = queryParamsSchema.parse({
      cursor: 'my-article-slug',
    });

    expect(parsed.pagination.cursor).toBe('my-article-slug');
    expect(typeof parsed.pagination.cursor).toBe('string');

    const v = validatorSchema(parsed.pagination);

    // String cursor in response
    expect(() =>
      v.parse({
        data: [{ slug: 'next-slug', title: 'Next' }],
        pagination: { itemsPerPage: 10, cursor: 'next-slug' },
      }),
    ).not.toThrow();

    // Number cursor should fail for string property
    expect(() =>
      v.parse({
        data: [{ slug: 'next-slug', title: 'Next' }],
        pagination: { itemsPerPage: 10, cursor: 123 },
      }),
    ).toThrow();
  });

  it('handles querystring array format for filters', () => {
    const { queryParamsSchema } = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: UserSchema,
      selectable: ['id', 'username', 'role'],
      defaultLimit: 20,
      maxLimit: 100,
      defaultSelect: ['id', 'username', 'role'],
      filterable: {
        role: { type: 'string', ops: ['$eq', '$in'] },
      },
    });

    // Simulates ?filter.role[]=$eq:admin&filter.role[]=$or:$eq:editor
    const parsed = queryParamsSchema.parse({
      'filter.role': ['$eq:admin', '$or:$eq:editor'],
    });

    const leaves = collectLeaves(parsed.pagination.filters);
    expect(leaves).toHaveLength(2);
  });

  it('pagination response with sortBy and filter metadata is accepted', () => {
    const { queryParamsSchema, validatorSchema } = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: ArticleSchema,
      selectable: ['id', 'title', 'status'],
      sortable: ['id'],
      filterable: {
        status: { type: 'string', ops: ['$eq'] },
      },
      defaultLimit: 20,
      maxLimit: 100,
      defaultSelect: ['id', 'title'],
    });

    const parsed = queryParamsSchema.parse({
      sortBy: 'id:ASC',
      'filter.status': '$eq:published',
    });

    const v = validatorSchema(parsed.pagination);

    expect(() =>
      v.parse({
        data: [{ id: 1, title: 'Hello' }],
        pagination: {
          itemsPerPage: 10,
          totalItems: 1,
          currentPage: 1,
          totalPages: 1,
          sortBy: [{ property: 'id', direction: 'ASC' }],
          filter: {
            type: 'filter',
            field: 'status',
            condition: {
              group: '0',
              op: '$eq',
              value: 'published',
            },
          },
        },
      }),
    ).not.toThrow();
  });
});

/* ========================================================================= */
/*  OpenAPI compatibility: queryParamsSchema exposes named properties         */
/* ========================================================================= */

/**
 * Unwrap the root ZodObject from a pipeline/transform chain,
 * mimicking what zod-openapi does.
 */
function unwrapRootZodObject(schema: z.ZodType): Record<string, unknown> | undefined {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let current: any = schema;

  for (let i = 0; i < 10; i++) {
    const def = current?._zod?.def;
    if (!def) return undefined;

    if (def.type === 'object' && typeof def.shape === 'object' && def.shape !== null) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return def.shape;
    }

    if (def.type === 'pipe' && def.in) {
      current = def.in;
      continue;
    }

    return undefined;
  }

  return undefined;
}

describe('OpenAPI compatibility: queryParamsSchema exposes named properties', () => {
  it('LIMIT_OFFSET schema exposes limit, page, sortBy, select', () => {
    const { queryParamsSchema } = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: UserSchema,
      selectable: ['id', 'username'],
      sortable: ['id'],
      defaultLimit: 20,
      maxLimit: 100,
      defaultSelect: '*',
    });

    const shape = unwrapRootZodObject(queryParamsSchema);
    expect(shape).toBeDefined();

    const keys = Object.keys(shape ?? {});
    expect(keys).toContain('limit');
    expect(keys).toContain('page');
    expect(keys).toContain('sortBy');
    expect(keys).toContain('select');
    expect(keys).not.toContain('cursor');
  });

  it('CURSOR schema exposes limit, cursor but not page', () => {
    const { queryParamsSchema } = paginate({
      paginationType: 'CURSOR',
      dataSchema: ArticleSchema,
      cursorProperty: 'id',
      selectable: ['id', 'title'],
      sortable: ['id'],
      defaultLimit: 20,
      maxLimit: 50,
      defaultSelect: ['id', 'title'],
    });

    const shape = unwrapRootZodObject(queryParamsSchema);
    expect(shape).toBeDefined();

    const keys = Object.keys(shape ?? {});
    expect(keys).toContain('limit');
    expect(keys).toContain('cursor');
    expect(keys).toContain('sortBy');
    expect(keys).toContain('select');
    expect(keys).not.toContain('page');
  });

  it('schema without sortable/selectable omits sortBy/select', () => {
    const { queryParamsSchema } = paginate({
      paginationType: 'LIMIT_OFFSET',
      dataSchema: UserSchema,
      defaultLimit: 10,
      maxLimit: 50,
      defaultSelect: '*',
    });

    const shape = unwrapRootZodObject(queryParamsSchema);
    expect(shape).toBeDefined();

    const keys = Object.keys(shape ?? {});
    expect(keys).toContain('limit');
    expect(keys).toContain('page');
    expect(keys).not.toContain('sortBy');
    expect(keys).not.toContain('select');
  });

  it('select() standalone exposes select property', () => {
    const { queryParamsSchema } = select({
      dataSchema: UserSchema,
      selectable: ['id', 'username'],
      defaultSelect: ['id'],
    });

    const shape = unwrapRootZodObject(queryParamsSchema);
    expect(shape).toBeDefined();

    const keys = Object.keys(shape ?? {});
    expect(keys).toContain('select');
  });
});
