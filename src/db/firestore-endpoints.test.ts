import { streamPipeline } from './firestore-endpoints.js';
import { executePipeline } from './firestore-endpoints.js';
import { WriteResult } from './write-request.js';
import { batchWrite } from './firestore-endpoints.js';
it('serializes transaction selectors for bulk, query and aggregate reads', async () => {
    const name = 'projects/p/databases/db/documents/users/a';
    const time = '2026-01-01T00:00:00.000000001Z';
    const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json([{ missing: name, readTime: time }])
        )
        .mockResolvedValueOnce(Response.json([{ readTime: time }]))
        .mockResolvedValueOnce(
            Response.json([
                {
                    result: {
                        aggregateFields: { agg_0: { integerValue: '1' } }
                    },
                    readTime: time
                }
            ])
        );
    const bulk = await batchGetDocuments(
        'p',
        'db',
        ['users/a'],
        'token',
        fetchFn,
        ['name'],
        'tx'
    );
    expect(
        (bulk as { readTimes?: Timestamp[] }).readTimes?.[0]?.nanoseconds
    ).toBe(1);
    await runQuery('p', 'db', 'users', {}, 'token', fetchFn, 'tx');
    const aggregate = await runAggregate(
        'p',
        'db',
        'users',
        {},
        { count: AggregateField.count() },
        'token',
        fetchFn,
        'tx'
    );
    expect((aggregate as any)[aggregateReadTime].nanoseconds).toBe(1);
    for (const call of fetchFn.mock.calls)
        expect(JSON.parse(call[1].body).transaction).toBe('tx');
    expect(JSON.parse(fetchFn.mock.calls[0]![1].body).mask).toEqual({
        fieldPaths: ['name']
    });
});

it('streams explain documents and normalized metrics through the endpoint layer', async () => {
    const name = 'projects/p/databases/db/documents/users/a';
    const fetchFn = vi.fn().mockResolvedValue(
        Response.json([
            {
                document: { name },
                readTime: '2026-01-01T00:00:00Z',
                explainMetrics: {
                    planSummary: {},
                    executionStats: {
                        resultsReturned: '1',
                        readOperations: '1',
                        executionDuration: '0.1s'
                    }
                }
            }
        ])
    );
    const abort = new AbortController();
    const rows = [];
    for await (const row of streamQueryRows(
        'p',
        'db',
        'users',
        {},
        'token',
        fetchFn,
        abort.signal,
        { analyze: true }
    ))
        rows.push(row);
    expect(rows[0]?.document?.name).toBe(name);
    expect(
        rows[1]?.metrics?.executionStats?.executionDuration.nanoseconds
    ).toBe(100000000);
    expect(JSON.parse(fetchFn.mock.calls[0]![1].body).explainOptions).toEqual({
        analyze: true
    });
    expect(fetchFn.mock.calls[0]![1].signal).toBe(abort.signal);
});

it('explains aggregates without execution and with result metadata', async () => {
    const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json([{ explainMetrics: { planSummary: {} } }])
        )
        .mockResolvedValueOnce(
            Response.json([
                {
                    result: {
                        aggregateFields: { agg_0: { integerValue: '2' } }
                    },
                    readTime: '2026-01-01T00:00:00Z',
                    explainMetrics: { planSummary: {}, executionStats: {} }
                }
            ])
        );
    const plan = await runAggregate(
        'p',
        'db',
        'users',
        {},
        { count: AggregateField.count() },
        'token',
        fetchFn,
        undefined,
        {}
    );
    expect((plan as any)[aggregateMetrics]).toEqual({
        planSummary: { indexesUsed: [] },
        executionStats: null
    });
    const result = await runAggregate(
        'p',
        'db',
        'users',
        {},
        { count: AggregateField.count() },
        'token',
        fetchFn,
        undefined,
        { analyze: true }
    );
    expect(result).toEqual({ count: 2 });
    expect((result as any)[aggregateReadTime]).toBeInstanceOf(Timestamp);
    expect(JSON.parse(fetchFn.mock.calls[1]![1].body).explainOptions).toEqual({
        analyze: true
    });
});
it('sorts non-ASCII partition paths using Firestore UTF-8 ordering', async () => {
    const prefix = 'projects/p/databases/db/documents/posts/';
    const fetchFn = vi.fn().mockResolvedValue(
        Response.json({
            partitions: ['\u{1f600}', '\ue000'].map((id) => ({
                values: [{ referenceValue: prefix + id }]
            }))
        })
    );
    const paths = await partitionQuery('p', 'db', 'posts', 3, 'token', fetchFn);
    expect(paths).toEqual(['posts/\ue000', 'posts/\u{1f600}']);
});
import { FirebaseEdgeError } from '../auth/errors.js';

it.each([
    [
        { status: 'PERMISSION_DENIED', message: 'Access denied' },
        'firestore/permission-denied',
        'Access denied'
    ],
    [
        { status: 123, message: false },
        'firestore/unknown',
        'Firestore request failed.'
    ],
    [{}, 'firestore/unknown', 'Firestore request failed.']
])(
    'maps REST failures to structured errors and preserves their cause',
    async (details, code, message) => {
        const fetchFn = vi.fn().mockResolvedValue(
            new Response(JSON.stringify({ error: details }), {
                status: 403,
                headers: { 'content-type': 'application/json' }
            })
        );
        await expect(
            getDocument('p', '(default)', 'users/a', 'token', fetchFn)
        ).rejects.toMatchObject({
            name: 'FirebaseEdgeError',
            code,
            message,
            cause: expect.any(Error)
        });
    }
);

it('classifies malformed successful responses as internal errors', async () => {
    const fetchFn = vi.fn().mockResolvedValue(
        new Response('{}', {
            headers: { 'content-type': 'application/json' }
        })
    );
    await expect(
        getDocument('p', '(default)', 'users/a', 'token', fetchFn)
    ).rejects.toMatchObject({
        name: 'FirebaseEdgeError',
        code: 'firestore/internal'
    });
});
import { expect, it, vi } from 'vitest';
import {
    getDocument,
    runQuery,
    commitWrites,
    beginTransaction,
    rollbackTransaction,
    runAggregate,
    createDocumentName,
    batchGetDocuments,
    listCollectionIds,
    listDocumentPaths,
    streamQuery,
    partitionQuery,
    configureFirestoreFetch,
    streamQueryRows
} from './firestore-endpoints.js';
import { AggregateField } from './aggregate.js';
import { Timestamp } from './timestamp.js';
import { aggregateReadTime, aggregateMetrics } from './aggregate.js';

it('requests read-only transactions and serializes nanosecond read times', async () => {
    const fetchFn = vi.fn().mockResolvedValue(
        new Response('{"transaction":"ro"}', {
            headers: { 'content-type': 'application/json' }
        })
    );
    const result = await beginTransaction('p', 'db', 'token', fetchFn, {
        readOnly: true,
        readTime: new Timestamp(1700000000, 123456000)
    });
    expect(result).toBe('ro');
    expect(JSON.parse(fetchFn.mock.calls[0]![1].body)).toEqual({
        options: { readOnly: { readTime: '2023-11-14T22:13:20.123456000Z' } }
    });
});

it('paginates partition cursors, sorts and deduplicates split points', async () => {
    const prefix = 'projects/p/databases/db/documents/';
    const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(
            new Response(
                JSON.stringify({
                    partitions: [
                        { values: [{ referenceValue: `${prefix}posts/z` }] }
                    ],
                    nextPageToken: 'next'
                }),
                { headers: { 'content-type': 'application/json' } }
            )
        )
        .mockResolvedValueOnce(
            new Response(
                JSON.stringify({
                    partitions: [
                        { values: [{ referenceValue: `${prefix}posts/a` }] },
                        { values: [{ referenceValue: `${prefix}posts/z` }] }
                    ]
                }),
                { headers: { 'content-type': 'application/json' } }
            )
        );
    const paths = await partitionQuery('p', 'db', 'posts', 4, 'token', fetchFn);
    expect(paths).toEqual(['posts/a', 'posts/z']);
    expect(fetchFn.mock.calls[0]![0]).toBe(
        'https://firestore.googleapis.com/v1/projects/p/databases/db/documents:partitionQuery'
    );
    expect(JSON.parse(fetchFn.mock.calls[1]![1].body)).toEqual({
        structuredQuery: {
            from: [{ collectionId: 'posts', allDescendants: true }],
            orderBy: [
                { field: { fieldPath: '__name__' }, direction: 'ASCENDING' }
            ]
        },
        partitionCount: '3',
        pageSize: 1000,
        pageToken: 'next'
    });
});

it.each([
    null,
    { partitions: false },
    { nextPageToken: 1 },
    { partitions: [{}] },
    {
        partitions: [
            {
                values: [
                    {
                        referenceValue:
                            'projects/other/databases/db/documents/posts/a'
                    }
                ]
            }
        ]
    },
    {
        partitions: [
            {
                values: [
                    {
                        referenceValue:
                            'projects/p/databases/db/documents/posts/a/child'
                    }
                ]
            }
        ]
    }
])('rejects malformed partition responses: %j', async (response) => {
    const fetchFn = vi.fn().mockResolvedValue(
        new Response(JSON.stringify(response), {
            headers: { 'content-type': 'application/json' }
        })
    );
    await expect(
        partitionQuery('p', 'db', 'posts', 2, 'token', fetchFn)
    ).rejects.toMatchObject({ code: 'firestore/internal' });
});

it('handles empty partition results, repeated pages and API errors', async () => {
    const fetchFn = vi.fn().mockImplementation(
        async () =>
            new Response('{}', {
                headers: { 'content-type': 'application/json' }
            })
    );
    const empty = await partitionQuery('p', 'db', 'posts', 2, 'token', fetchFn);
    expect(empty).toEqual([]);
    fetchFn.mockImplementation(
        async () =>
            new Response('{"nextPageToken":"same"}', {
                headers: { 'content-type': 'application/json' }
            })
    );
    await expect(
        partitionQuery('p', 'db', 'posts', 2, 'token', fetchFn)
    ).rejects.toThrow('Repeated');
    fetchFn.mockImplementation(
        async () =>
            new Response('{"error":{"status":"PERMISSION_DENIED"}}', {
                status: 403,
                headers: { 'content-type': 'application/json' }
            })
    );
    await expect(
        partitionQuery('p', 'db', 'posts', 2, 'token', fetchFn)
    ).rejects.toMatchObject({ code: 'firestore/permission-denied' });
});

it('configures only Firestore REST destinations and preserves OAuth destinations', async () => {
    const fetchFn = vi.fn().mockResolvedValue(new Response('{}'));
    const configured = configureFirestoreFetch(
        fetchFn,
        'localhost:8080',
        false
    );
    await configured(
        'https://firestore.googleapis.com/v1/projects/p/databases/db/documents/users/a?mask=x',
        { method: 'GET' }
    );
    expect(fetchFn).toHaveBeenLastCalledWith(
        'http://localhost:8080/v1/projects/p/databases/db/documents/users/a?mask=x',
        { method: 'GET' }
    );
    await configured('https://oauth2.googleapis.com/token', { method: 'POST' });
    expect(fetchFn).toHaveBeenLastCalledWith(
        'https://oauth2.googleapis.com/token',
        { method: 'POST' }
    );
    const secure = configureFirestoreFetch(fetchFn, 'example.com');
    await secure('https://firestore.googleapis.com/v1/test');
    expect(fetchFn).toHaveBeenLastCalledWith(
        'https://example.com/v1/test',
        undefined
    );
    for (const host of [
        '',
        'https://example.com',
        'example.com/path',
        'user@example.com',
        'a b'
    ])
        expect(() => configureFirestoreFetch(fetchFn, host)).toThrow(
            FirebaseEdgeError
        );
});

it('preserves server read times including empty query results', async () => {
    const fetchFn = vi.fn().mockResolvedValue(
        new Response('[{"readTime":"2023-11-14T22:13:20.123456000Z"}]', {
            headers: { 'content-type': 'application/json' }
        })
    );
    const result = await runQuery('p', 'db', 'posts', {}, 'token', fetchFn);
    expect(result).toHaveLength(0);
    expect((result as typeof result & { readTime: string }).readTime).toBe(
        '2023-11-14T22:13:20.123456000Z'
    );
});

it('batch-reads unique names and restores requested order, duplicates and missing documents', async () => {
    const prefix = 'projects/p/databases/db/documents/';
    const a = {
        name: `${prefix}users/a`,
        fields: { n: { integerValue: '1' } }
    };
    const fetchFn = vi
        .fn()
        .mockResolvedValue(
            Response.json([{ missing: `${prefix}users/b` }, { found: a }])
        );
    const results = await batchGetDocuments(
        'p',
        'db',
        ['users/a', 'users/b', 'users/a'],
        'token',
        fetchFn,
        ['n']
    );
    expect(results).toEqual([a, undefined, a]);
    expect(fetchFn.mock.calls[0]![0]).toContain('/documents:batchGet');
    expect(JSON.parse(fetchFn.mock.calls[0]![1].body)).toEqual({
        documents: [`${prefix}users/a`, `${prefix}users/b`],
        mask: { fieldPaths: ['n'] }
    });

    for (const response of [
        {},
        [],
        [{ found: { name: 'foreign' } }],
        [{ error: { status: 'PERMISSION_DENIED' } }]
    ]) {
        fetchFn.mockResolvedValueOnce(Response.json(response));
        await expect(
            batchGetDocuments('p', 'db', ['users/a'], 'token', fetchFn)
        ).rejects.toThrow();
    }
});

it('paginates root and nested collection listings', async () => {
    const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json({ collectionIds: ['posts'], nextPageToken: 'next' })
        )
        .mockResolvedValueOnce(Response.json({ collectionIds: ['comments'] }));
    const ids = await listCollectionIds(
        'p',
        'db',
        'users/a #',
        'token',
        fetchFn
    );
    expect(ids).toEqual(['posts', 'comments']);
    expect(fetchFn.mock.calls[0]![0]).toContain(
        '/documents/users/a%20%23:listCollectionIds'
    );
    expect(JSON.parse(fetchFn.mock.calls[1]![1].body).pageToken).toBe('next');
    fetchFn.mockResolvedValueOnce(Response.json({}));
    const empty = await listCollectionIds('p', 'db', '', 'token', fetchFn);
    expect(empty).toEqual([]);
    expect(fetchFn.mock.lastCall![0]).toContain('/documents:listCollectionIds');
    fetchFn.mockImplementation(async () =>
        Response.json({ nextPageToken: 'loop' })
    );
    await expect(
        listCollectionIds('p', 'db', '', 'token', fetchFn)
    ).rejects.toThrow('Repeated');
    fetchFn.mockResolvedValue(Response.json({ collectionIds: ['bad/id'] }));
    await expect(
        listCollectionIds('p', 'db', '', 'token', fetchFn)
    ).rejects.toThrow('Invalid');
});

it('lists document paths including missing parents and follows page tokens', async () => {
    const prefix = 'projects/p/databases/db/documents/';
    const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json({
                documents: [{ name: `${prefix}users/a` }],
                nextPageToken: 'a+/'
            })
        )
        .mockResolvedValueOnce(
            Response.json({ documents: [{ name: `${prefix}users/missing` }] })
        );
    const paths = await listDocumentPaths('p', 'db', 'users', 'token', fetchFn);
    expect(paths).toEqual(['users/a', 'users/missing']);
    expect(fetchFn.mock.calls[0]![0]).toContain('showMissing=true');
    expect(fetchFn.mock.calls[1]![0]).toContain('pageToken=a%2B%2F');
    fetchFn.mockResolvedValue(
        Response.json({ documents: [{ name: `${prefix}other/a` }] })
    );
    await expect(
        listDocumentPaths('p', 'db', 'users', 'token', fetchFn)
    ).rejects.toThrow('Invalid');
    fetchFn.mockImplementation(async () =>
        Response.json({ nextPageToken: 'loop' })
    );
    await expect(
        listDocumentPaths('p', 'db', 'users', 'token', fetchFn)
    ).rejects.toThrow('Repeated');
    fetchFn.mockResolvedValue(
        Response.json(
            { error: { status: 'PERMISSION_DENIED' } },
            { status: 403 }
        )
    );
    await expect(
        listDocumentPaths('p', 'db', 'users', 'token', fetchFn)
    ).rejects.toMatchObject({ code: 'firestore/permission-denied' });
});

it('streams authenticated query rows incrementally and forwards AbortSignal', async () => {
    const abort = new AbortController();
    const document = { name: 'projects/p/databases/db/documents/users/a' };
    const fetchFn = vi
        .fn()
        .mockResolvedValue(
            Response.json([{ readTime: '2026-01-01T00:00:00Z' }, { document }])
        );
    const documents = [];
    for await (const result of streamQuery(
        'p',
        'db',
        'users',
        { limit: 1 },
        'token',
        fetchFn,
        abort.signal
    ))
        documents.push(result);
    expect(documents).toEqual([document]);
    expect(fetchFn).toHaveBeenCalledWith(
        'https://firestore.googleapis.com/v1/projects/p/databases/db/documents:runQuery',
        expect.objectContaining({
            signal: abort.signal,
            method: 'POST',
            headers: expect.objectContaining({ Authorization: 'Bearer token' })
        })
    );
    expect(
        JSON.parse(fetchFn.mock.calls[0]![1].body).structuredQuery.limit
    ).toBe(1);
});

it('surfaces stream HTTP errors, embedded errors and invalid documents', async () => {
    for (const response of [
        Response.json(
            { error: { status: 'PERMISSION_DENIED' } },
            { status: 403 }
        ),
        new Response('offline', { status: 503 }),
        Response.json([{ error: { status: 'INTERNAL' } }]),
        Response.json([{ document: { name: 'foreign' } }]),
        new Response(null, { status: 204 })
    ]) {
        const iterator = streamQuery(
            'p',
            'db',
            'users',
            {},
            'token',
            vi.fn().mockResolvedValue(response)
        );
        await expect(iterator.next()).rejects.toThrow();
    }
});

it('constructs resource names and sends atomic commit writes with masks, transforms and conditions', async () => {
    expect(createDocumentName('p', 'db', '')).toBe(
        'projects/p/databases/db/documents'
    );
    const fetchFn = vi.fn().mockResolvedValue(
        Response.json({
            writeResults: [
                { updateTime: '2026-01-01T00:00:00.123456789Z' },
                {}
            ],
            commitTime: '2026-01-01T00:00:01Z'
        })
    );
    const result = await commitWrites(
        'p',
        'db',
        [
            {
                path: 'users/a',
                kind: 'update',
                fields: { n: { integerValue: '2' } },
                mask: ['n'],
                transforms: [
                    { fieldPath: 'time', setToServerValue: 'REQUEST_TIME' }
                ],
                precondition: { exists: true }
            },
            { path: 'users/b', kind: 'delete' }
        ],
        'token',
        fetchFn,
        'transaction'
    );
    expect(fetchFn.mock.calls[0]![0]).toBe(
        'https://firestore.googleapis.com/v1/projects/p/databases/db/documents:commit'
    );
    expect(JSON.parse(fetchFn.mock.calls[0]![1].body)).toEqual({
        transaction: 'transaction',
        writes: [
            {
                update: {
                    name: 'projects/p/databases/db/documents/users/a',
                    fields: { n: { integerValue: '2' } }
                },
                updateMask: { fieldPaths: ['n'] },
                updateTransforms: [
                    { fieldPath: 'time', setToServerValue: 'REQUEST_TIME' }
                ],
                currentDocument: { exists: true }
            },
            { delete: 'projects/p/databases/db/documents/users/b' }
        ]
    });
    expect(result[0]!.writeTime).toBeInstanceOf(Timestamp);
    expect(result[0]!.writeTime.nanoseconds).toBe(123456789);
    expect(result[1]!.writeTime.toString()).toBe(
        '2026-01-01T00:00:01.000000000Z'
    );
});

it('begins, reads and rolls back using the same transaction ID', async () => {
    const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(Response.json({ transaction: 'a+/=' }))
        .mockResolvedValueOnce(
            Response.json([
                {
                    found: {
                        name: 'projects/p/databases/db/documents/users/a'
                    },
                    readTime: '2026-01-01T00:00:00Z'
                }
            ])
        )
        .mockResolvedValueOnce(Response.json({}));
    const id = await beginTransaction('p', 'db', 'token', fetchFn);
    expect(JSON.parse(fetchFn.mock.calls[0]![1].body)).toEqual({
        options: { readWrite: {} }
    });
    await getDocument('p', 'db', 'users/a', 'token', fetchFn, id);
    expect(JSON.parse(fetchFn.mock.calls[1]![1].body).transaction).toBe('a+/=');
    await rollbackTransaction('p', 'db', id, 'token', fetchFn);
    expect(fetchFn.mock.calls[2]![0]).toContain(':rollback');
    expect(JSON.parse(fetchFn.mock.calls[2]![1].body)).toEqual({
        transaction: id
    });
});

it('validates transaction/commit responses and maps errors', async () => {
    await expect(
        beginTransaction(
            'p',
            'db',
            't',
            vi.fn().mockResolvedValue(Response.json({}))
        )
    ).rejects.toThrow('transaction ID');
    await expect(
        commitWrites(
            'p',
            'db',
            [{ path: 'users/a', kind: 'delete' }],
            't',
            vi.fn().mockResolvedValue(Response.json({}))
        )
    ).rejects.toThrow('commit response');
    await expect(
        commitWrites(
            'p',
            'db',
            [],
            't',
            vi
                .fn()
                .mockResolvedValue(
                    Response.json({ commitTime: '2026-01-01T00:00:00Z' })
                ),
            'tx'
        )
    ).resolves.toEqual([]);
    await expect(
        commitWrites(
            'p',
            'db',
            [],
            't',
            vi
                .fn()
                .mockResolvedValue(
                    Response.json(
                        { error: { status: 'ABORTED', message: 'retry' } },
                        { status: 409 }
                    )
                )
        )
    ).rejects.toMatchObject({ code: 'firestore/aborted' });
});

it('sends server aggregates for a nested filtered query and safely maps aliases', async () => {
    const fetchFn = vi.fn().mockResolvedValue(
        Response.json([
            { readTime: '2026-01-01T00:00:00Z' },
            {
                result: {
                    aggregateFields: {
                        agg_0: { integerValue: '3' },
                        agg_1: { doubleValue: 12.5 },
                        agg_2: { nullValue: null }
                    }
                }
            }
        ])
    );
    const result = await runAggregate(
        'p',
        'db',
        'users/a/posts',
        { limit: 10 },
        {
            'total.count': AggregateField.count(),
            sum: AggregateField.sum('price'),
            avg: AggregateField.average('price')
        },
        'token',
        fetchFn
    );
    expect(result).toEqual({ 'total.count': 3, sum: 12.5, avg: null });
    expect(fetchFn.mock.calls[0]![0]).toBe(
        'https://firestore.googleapis.com/v1/projects/p/databases/db/documents/users/a:runAggregationQuery'
    );
    expect(JSON.parse(fetchFn.mock.calls[0]![1].body)).toEqual({
        structuredAggregationQuery: {
            structuredQuery: { from: [{ collectionId: 'posts' }], limit: 10 },
            aggregations: [
                { alias: 'agg_0', count: {} },
                { alias: 'agg_1', sum: { field: { fieldPath: 'price' } } },
                { alias: 'agg_2', avg: { field: { fieldPath: 'price' } } }
            ]
        }
    });
});

it('rejects malformed aggregate results and row errors', async () => {
    for (const response of [
        {},
        [],
        [{ result: {} }],
        [{ error: { status: 'INTERNAL' } }],
        [{ result: { aggregateFields: { agg_0: { stringValue: 'bad' } } } }]
    ]) {
        await expect(
            runAggregate(
                'p',
                'db',
                'users',
                {},
                { n: AggregateField.count() },
                't',
                vi.fn().mockResolvedValue(Response.json(response))
            )
        ).rejects.toThrow();
    }
});

it('posts structured queries and skips metadata-only response rows', async () => {
    const document = { name: 'projects/p/databases/db/documents/users/a' };
    const fetchFn = vi
        .fn()
        .mockResolvedValue(
            Response.json([
                { readTime: 'now' },
                { document },
                { skippedResults: 2 }
            ])
        );
    await expect(
        runQuery('p', 'db', 'users', { limit: 2 }, 'token', fetchFn)
    ).resolves.toEqual([document]);
    expect(fetchFn).toHaveBeenCalledWith(
        'https://firestore.googleapis.com/v1/projects/p/databases/db/documents:runQuery',
        expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({ Authorization: 'Bearer token' }),
            body: JSON.stringify({
                structuredQuery: { from: [{ collectionId: 'users' }], limit: 2 }
            })
        })
    );
});

it('uses the parent document for nested collection queries and encodes path segments', async () => {
    const fetchFn = vi
        .fn()
        .mockResolvedValue(Response.json([{ readTime: 'now' }]));
    await expect(
        runQuery('p', 'db', 'users/a #/posts', {}, 'token', fetchFn)
    ).resolves.toEqual([]);
    expect(fetchFn.mock.calls[0]![0]).toBe(
        'https://firestore.googleapis.com/v1/projects/p/databases/db/documents/users/a%20%23:runQuery'
    );
    expect(
        JSON.parse(fetchFn.mock.calls[0]![1].body).structuredQuery.from
    ).toEqual([{ collectionId: 'posts' }]);
});

it('propagates query API errors including missing indexes and missing databases', async () => {
    for (const status of [
        'FAILED_PRECONDITION',
        'NOT_FOUND',
        'PERMISSION_DENIED'
    ]) {
        const fetchFn = vi
            .fn()
            .mockResolvedValue(
                Response.json(
                    { error: { status, message: 'details' } },
                    { status: 400 }
                )
            );
        await expect(
            runQuery('p', 'db', 'users', {}, 'token', fetchFn)
        ).rejects.toMatchObject({
            code: `firestore/${status.toLowerCase().replaceAll('_', '-')}`,
            message: 'details'
        });
    }
});

it('rejects malformed query responses, stream errors, text errors and network errors', async () => {
    for (const response of [
        {},
        [null],
        [{ document: {} }],
        [
            {
                document: {
                    name: 'projects/other/databases/db/documents/users/a'
                }
            }
        ],
        [{ error: { status: 'INTERNAL' } }]
    ]) {
        await expect(
            runQuery(
                'p',
                'db',
                'users',
                {},
                't',
                vi.fn().mockResolvedValue(Response.json(response))
            )
        ).rejects.toThrow();
    }
    await expect(
        runQuery(
            'p',
            'db',
            'users',
            {},
            't',
            vi
                .fn()
                .mockResolvedValue(new Response('Unavailable', { status: 503 }))
        )
    ).rejects.toMatchObject({ code: 'firestore/unknown' });
    await expect(
        runQuery(
            'p',
            'db',
            'users',
            {},
            't',
            vi.fn().mockRejectedValue(new Error('offline'))
        )
    ).rejects.toThrow('offline');
});

it('reads a single document using batchGet and preserves its server read time', async () => {
    const document = {
        name: 'projects/project/databases/(default)/documents/users/a #?',
        readTime: '2026-01-01T00:00:00Z'
    };
    const fetchFn = vi
        .fn()
        .mockResolvedValue(
            Response.json([
                { found: { name: document.name }, readTime: document.readTime }
            ])
        );
    await expect(
        getDocument('project', '(default)', 'users/a #?', 'token', fetchFn)
    ).resolves.toEqual(document);
    expect(fetchFn).toHaveBeenCalledWith(
        'https://firestore.googleapis.com/v1/projects/project/databases/(default)/documents:batchGet',
        expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({ documents: [document.name] }),
            headers: expect.objectContaining({ Authorization: 'Bearer token' })
        })
    );
});

it('preserves server read time for missing documents and rejects a missing database', async () => {
    const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json([
                {
                    missing: 'projects/p/databases/db/documents/users/a',
                    readTime: '2026-01-01T00:00:00Z'
                }
            ])
        )
        .mockResolvedValue(
            Response.json({ error: { status: 'NOT_FOUND' } }, { status: 404 })
        );
    await expect(
        getDocument('p', 'db', 'users/a', 't', fetchFn)
    ).resolves.toEqual({
        name: 'projects/p/databases/db/documents/users/a',
        missing: true,
        readTime: '2026-01-01T00:00:00.000000000Z'
    });
    await expect(
        getDocument('p', 'db', 'users/a', 't', fetchFn)
    ).rejects.toMatchObject({ code: 'firestore/not-found' });
});

it('maps API errors and preserves their message', async () => {
    const fetchFn = vi
        .fn()
        .mockResolvedValue(
            Response.json(
                { error: { status: 'PERMISSION_DENIED', message: 'Denied' } },
                { status: 403 }
            )
        );
    await expect(
        getDocument('p', 'db', 'users/a', 't', fetchFn)
    ).rejects.toMatchObject({
        code: 'firestore/permission-denied',
        message: 'Denied'
    });
});

it('rejects text errors, malformed successful responses, and network failures', async () => {
    const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(new Response('Unavailable', { status: 503 }))
        .mockResolvedValueOnce(Response.json({}))
        .mockRejectedValueOnce(new Error('offline'));
    await expect(
        getDocument('p', 'db', 'users/a', 't', fetchFn)
    ).rejects.toMatchObject({ code: 'firestore/unknown' });
    await expect(
        getDocument('p', 'db', 'users/a', 't', fetchFn)
    ).rejects.toThrow('Invalid batchGet response');
    await expect(
        getDocument('p', 'db', 'users/a', 't', fetchFn)
    ).rejects.toThrow('offline');
});

it('serializes independent bulk writes and maps mixed statuses in request order', async () => {
    const time = '2025-01-01T00:00:00.123456789Z';
    const fetchFn = vi.fn().mockResolvedValue(
        Response.json({
            writeResults: [{ updateTime: time }, {}, {}, {}],
            status: [
                {},
                { code: 7, message: 'denied' },
                { code: 14, message: 'retry' },
                { code: 0 }
            ]
        })
    );
    const results = await batchWrite(
        'p',
        'db',
        [
            {
                path: 'users/a',
                kind: 'update',
                fields: { n: { integerValue: '1' } },
                mask: ['n'],
                transforms: [
                    { fieldPath: 'at', setToServerValue: 'REQUEST_TIME' }
                ],
                precondition: { exists: true }
            },
            {
                path: 'users/b',
                kind: 'create',
                fields: {},
                precondition: { exists: false }
            },
            { path: 'users/c', kind: 'set', fields: {} },
            {
                path: 'users/d',
                kind: 'delete',
                precondition: { updateTime: time }
            }
        ],
        'token',
        fetchFn
    );
    expect(results).toEqual([
        { writeTime: Timestamp.fromString(time) },
        expect.objectContaining({
            code: 'firestore/permission-denied',
            message: 'denied'
        }),
        expect.objectContaining({
            code: 'firestore/unavailable',
            message: 'retry'
        }),
        new WriteResult(new Timestamp(0, 0))
    ]);
    expect(fetchFn).toHaveBeenCalledWith(
        'https://firestore.googleapis.com/v1/projects/p/databases/db/documents:batchWrite',
        expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({ Authorization: 'Bearer token' })
        })
    );
    const body = JSON.parse(fetchFn.mock.calls[0]![1].body);
    expect(body.writes[0]).toEqual({
        update: {
            name: 'projects/p/databases/db/documents/users/a',
            fields: { n: { integerValue: '1' } }
        },
        updateMask: { fieldPaths: ['n'] },
        updateTransforms: [
            { fieldPath: 'at', setToServerValue: 'REQUEST_TIME' }
        ],
        currentDocument: { exists: true }
    });
    expect(body.writes[3]).toEqual({
        delete: 'projects/p/databases/db/documents/users/d',
        currentDocument: { updateTime: time }
    });
});

it('guards empty and duplicate bulk requests before transport', async () => {
    const fetchFn = vi.fn();
    await expect(batchWrite('p', 'db', [], 'token', fetchFn)).resolves.toEqual(
        []
    );
    const operation = { path: 'users/a', kind: 'delete' as const };
    await expect(
        batchWrite('p', 'db', [operation, operation], 'token', fetchFn)
    ).rejects.toThrow('distinct');
    expect(fetchFn).not.toHaveBeenCalled();
});

it.each([
    {},
    { writeResults: [], status: [] },
    { writeResults: [{}], status: [] }
])('rejects incomplete batchWrite responses', async (response) => {
    const fetchFn = vi.fn().mockResolvedValue(Response.json(response));
    await expect(
        batchWrite(
            'p',
            'db',
            [{ path: 'users/a', kind: 'set', fields: {} }],
            'token',
            fetchFn
        )
    ).rejects.toMatchObject({ code: 'firestore/internal' });
});

it.each([
    { status: [null], writeResults: [{}] },
    { status: [{ code: -1 }], writeResults: [{}] },
    { status: [{ code: '7' }], writeResults: [{}] },
    { status: [{}], writeResults: [null] },
    { status: [{}], writeResults: [{}] },
    { status: [{}], writeResults: [{ updateTime: 'bad' }] }
])(
    'isolates malformed per-write results as internal errors',
    async (response) => {
        const fetchFn = vi.fn().mockResolvedValue(Response.json(response));
        const results = await batchWrite(
            'p',
            'db',
            [{ path: 'users/a', kind: 'set', fields: {} }],
            'token',
            fetchFn
        );
        expect(results[0]).toMatchObject({ code: 'firestore/internal' });
    }
);

it('splits UTF-8 payloads and preserves successful chunks when a later request fails', async () => {
    const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(
            Response.json({
                status: [{}],
                writeResults: [{ updateTime: '2025-01-01T00:00:00Z' }]
            })
        )
        .mockResolvedValueOnce(
            Response.json(
                { error: { status: 'UNAVAILABLE', message: 'retry' } },
                { status: 503 }
            )
        );
    const fields = { text: { stringValue: '界'.repeat(1600000) } };
    const results = await batchWrite(
        'p',
        'db',
        [
            { path: 'users/a', kind: 'set', fields },
            { path: 'users/b', kind: 'set', fields }
        ],
        'token',
        fetchFn
    );
    expect(fetchFn).toHaveBeenCalledTimes(2);
    expect(results[0]).toMatchObject({ writeTime: expect.any(Timestamp) });
    expect(results[1]).toMatchObject({ code: 'firestore/unavailable' });
    for (const call of fetchFn.mock.calls)
        expect(new TextEncoder().encode(call[1].body).byteLength).toBeLessThan(
            9 * 1024 * 1024
        );
    await expect(
        batchWrite(
            'p',
            'db',
            [
                {
                    path: 'users/c',
                    kind: 'set',
                    fields: { text: { stringValue: '界'.repeat(3200000) } }
                }
            ],
            'token',
            fetchFn
        )
    ).rejects.toThrow('size limit');
    expect(fetchFn).toHaveBeenCalledTimes(2);
});

it('rejects malformed pagination envelopes and handles non-object stream errors', async () => {
    for (const page of ['text', [], { nextPageToken: 3 }]) {
        const fetchFn = vi
            .fn()
            .mockImplementation(async () => Response.json(page));
        await expect(
            listCollectionIds('p', 'db', '', 'token', fetchFn)
        ).rejects.toThrow('Invalid');
        await expect(
            listDocumentPaths('p', 'db', 'users', 'token', fetchFn)
        ).rejects.toThrow('Invalid');
    }
    const iterator = streamQuery(
        'p',
        'db',
        'users',
        {},
        'token',
        vi.fn().mockResolvedValue(Response.json(null, { status: 500 }))
    );
    await expect(iterator.next()).rejects.toMatchObject({
        code: 'firestore/unknown'
    });
});

it('preserves streamed REST error status and message', async () => {
    const fetchFn = vi.fn().mockResolvedValue(
        Response.json(
            [
                {
                    error: {
                        status: 'FAILED_PRECONDITION',
                        message: 'Missing vector index'
                    }
                }
            ],
            { status: 400 }
        )
    );
    await expect(
        runQuery('p', 'db', 'users', {}, 'token', fetchFn)
    ).rejects.toMatchObject({
        code: 'firestore/failed-precondition',
        message: 'Missing vector index'
    });
});

it('applies an explicit port at the transport boundary', async () => {
    const fetchFn = vi.fn().mockResolvedValue(Response.json({}));
    const configured = configureFirestoreFetch(
        fetchFn,
        'localhost',
        false,
        8082
    );
    await configured(
        'https://firestore.googleapis.com/v1/projects/p/databases/db/documents'
    );
    expect(String(fetchFn.mock.calls[0]![0])).toContain(
        'http://localhost:8082/v1/projects/p'
    );
});

it('executes REST pipelines with transaction selectors, empty batches and errors', async () => {
    const fetchFn = vi
        .fn()
        .mockResolvedValue(
            Response.json([
                { results: [{ fields: { n: { integerValue: '1' } } }] },
                { executionTime: '2026-01-01T00:00:00Z' }
            ])
        );
    const request = { pipeline: { stages: [{ name: 'database', args: [] }] } };
    const result = await executePipeline(
        'p',
        'db',
        request,
        'token',
        fetchFn,
        'tx'
    );
    expect(result.results).toHaveLength(1);
    expect(fetchFn.mock.calls[0]![0]).toContain('/documents:executePipeline');
    expect(JSON.parse(fetchFn.mock.calls[0]![1].body)).toEqual({
        structuredPipeline: request,
        transaction: 'tx'
    });
    await expect(
        executePipeline(
            'p',
            'db',
            request,
            'token',
            fetchFn,
            'tx',
            Timestamp.now()
        )
    ).rejects.toThrow('Choose');
    fetchFn.mockResolvedValue(
        Response.json([{ executionTime: '2026-01-01T00:00:00Z' }])
    );
    const empty = await executePipeline(
        'p',
        'db',
        request,
        'token',
        fetchFn,
        undefined,
        new Timestamp(0, 0)
    );
    expect(empty.results).toEqual([]);
    expect(JSON.parse(fetchFn.mock.lastCall![1].body).readTime).toBe(
        '1970-01-01T00:00:00.000000000Z'
    );
    for (const invalid of [
        {},
        [],
        [null],
        [{ results: {} }],
        [{ results: [null] }]
    ]) {
        fetchFn.mockResolvedValue(Response.json(invalid));
        await expect(
            executePipeline('p', 'db', request, 'token', fetchFn)
        ).rejects.toThrow();
    }
    fetchFn.mockResolvedValue(
        Response.json([
            { error: { status: 'PERMISSION_DENIED', message: 'denied' } }
        ])
    );
    await expect(
        executePipeline('p', 'db', request, 'token', fetchFn)
    ).rejects.toMatchObject({ code: 'firestore/permission-denied' });
});

it('streams pipeline batches and maps stream errors without buffering all results', async () => {
    const fetchFn = vi.fn().mockResolvedValue(
        Response.json([
            {
                results: [
                    { fields: { n: { integerValue: '1' } } },
                    { fields: { n: { integerValue: '2' } } }
                ]
            },
            { executionTime: '2026-01-01T00:00:00Z' }
        ])
    );
    const stream = streamPipeline(
        'p',
        'db',
        { pipeline: { stages: [] } },
        'token',
        fetchFn
    );
    const first = await stream.next();
    expect(first.value).toEqual({ fields: { n: { integerValue: '1' } } });
    await stream.return(undefined);
    const abort = new AbortController();
    abort.abort();
    await expect(
        streamPipeline('p', 'db', {}, 'token', fetchFn, abort.signal).next()
    ).rejects.toThrow();
    for (const body of [
        [null],
        [{ results: [null] }],
        [{ error: { status: 'PERMISSION_DENIED', message: 'denied' } }]
    ]) {
        fetchFn.mockResolvedValue(Response.json(body));
        await expect(
            streamPipeline('p', 'db', {}, 'token', fetchFn).next()
        ).rejects.toThrow();
    }
    fetchFn.mockResolvedValue(
        Response.json(
            [
                {
                    error: {
                        status: 'FAILED_PRECONDITION',
                        message: 'requires Enterprise'
                    }
                }
            ],
            { status: 400 }
        )
    );
    await expect(
        streamPipeline('p', 'db', {}, 'token', fetchFn).next()
    ).rejects.toMatchObject({ code: 'firestore/failed-precondition' });
    fetchFn.mockResolvedValue(new Response(null));
    await expect(
        streamPipeline('p', 'db', {}, 'token', fetchFn).next()
    ).rejects.toThrow('Missing pipeline stream');
});

it('instruments Firestore transport with an injected tracer without tracing OAuth', async () => {
    const span = { end: vi.fn(), recordException: vi.fn(), setStatus: vi.fn() };
    const startSpan = vi.fn().mockReturnValue(span);
    const fetchFn = vi.fn().mockResolvedValue(Response.json({}));
    const transport = configureFirestoreFetch(
        fetchFn,
        'firestore.googleapis.com',
        true,
        undefined,
        { tracerProvider: { getTracer: () => ({ startSpan }) } }
    );
    await transport('https://firestore.googleapis.com/v1/projects/p');
    expect(startSpan).toHaveBeenCalledWith('firestore.rest');
    expect(span.end).toHaveBeenCalledOnce();
    await transport('https://oauth2.googleapis.com/token');
    expect(startSpan).toHaveBeenCalledOnce();
    const failure = new Error('network');
    fetchFn.mockRejectedValue(failure);
    await expect(
        transport('https://firestore.googleapis.com/v1/projects/p')
    ).rejects.toBe(failure);
    expect(span.recordException).toHaveBeenCalledWith(failure);
    expect(span.end).toHaveBeenCalledTimes(2);
});

it('preserves Request metadata when remapping an observed transport', async () => {
    const fetchFn = vi.fn().mockResolvedValue(Response.json({ ok: true }));
    const configured = configureFirestoreFetch(
        fetchFn,
        'localhost',
        false,
        8080
    );
    const request = new Request(
        'https://firestore.googleapis.com/v1/projects/p',
        {
            method: 'POST',
            headers: { 'X-Test': 'retained' },
            body: '{"test":true}'
        }
    );
    const response = await configured(request);
    expect(response.ok).toBe(true);
    const forwarded = fetchFn.mock.calls[0]![0] as Request;
    expect(forwarded.url).toBe('http://localhost:8080/v1/projects/p');
    expect(forwarded.method).toBe('POST');
    expect(forwarded.headers.get('X-Test')).toBe('retained');
    const body = await forwarded.text();
    expect(body).toBe('{"test":true}');
});
