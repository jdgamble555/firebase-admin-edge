import { firestoreData } from './firestore-results.js';

it('returns query failures and invalid explain options as results', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const failure = new Error('offline');
    vi.spyOn(db, '_query').mockRejectedValue(failure);
    const query = db.collection('users');
    const result = await query.get();
    expect(result).toEqual({ error: failure, data: null });
    const { error, data } = await query.explain({
        analyze: 'invalid'
    } as never);
    expect(error).toBeInstanceOf(FirebaseEdgeError);
    expect(data).toBeNull();
});
import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it, vi } from 'vitest';
import { Query, QuerySnapshot } from './query.js';
import { Firestore } from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import { Filter } from './filter.js';
import { FieldPath } from './field-path.js';
import { AggregateField, AggregateQuery } from './aggregate.js';
import { DocumentSnapshot } from './document-snapshot.js';

it('polls query changes with replayable indices, preserves converters and stops on termination', async () => {
    vi.useFakeTimers();
    try {
        const db = new Firestore({ project_id: 'p' } as ServiceAccount);
        const a = {
            name: 'projects/p/databases/(default)/documents/users/a',
            fields: { n: { integerValue: '1' } }
        };
        const b = {
            name: 'projects/p/databases/(default)/documents/users/b',
            fields: { n: { integerValue: '2' } }
        };
        const c = {
            name: 'projects/p/databases/(default)/documents/users/c',
            fields: { n: { integerValue: '3' } }
        };
        const execute = vi
            .fn()
            .mockResolvedValueOnce([a, b])
            .mockResolvedValueOnce([a, b])
            .mockResolvedValueOnce([
                b,
                { ...a, fields: { n: { integerValue: '4' } } },
                c
            ])
            .mockResolvedValueOnce([c, b])
            .mockResolvedValue([]);
        const query = new Query(db, 'users', execute).withConverter({
            toFirestore: () => ({}),
            fromFirestore: (doc) => ({ number: doc.get('n') })
        });
        const next = vi.fn();
        query.onSnapshot(next, undefined, { pollIntervalMs: 10 });
        await vi.advanceTimersByTimeAsync(40);
        expect(next).toHaveBeenCalledTimes(4);
        expect(
            next.mock.calls[0]![0].docChanges().map(
                (change: { type: string }) => change.type
            )
        ).toEqual(['added', 'added']);
        const list: string[] = [];
        const types = new Set<string>();
        for (const [snapshot] of next.mock.calls) {
            for (const change of snapshot.docChanges()) {
                types.add(change.type);
                if (change.oldIndex >= 0)
                    expect(list.splice(change.oldIndex, 1)[0]).toBe(
                        change.doc.id
                    );
                if (change.newIndex >= 0)
                    list.splice(change.newIndex, 0, change.doc.id);
            }
            expect(list).toEqual(
                snapshot.docs.map((doc: { id: string }) => doc.id)
            );
        }
        expect(types).toEqual(new Set(['added', 'modified', 'removed']));
        expect(next.mock.calls[1]![0].docs[1].data()).toEqual({ number: 4 });
        const changes = next.mock.calls[1]![0].docChanges();
        changes[0].newIndex = 100;
        expect(next.mock.calls[1]![0].docChanges()[0].newIndex).not.toBe(100);
        await db.terminate().then(firestoreData);
        await vi.advanceTimersByTimeAsync(100);
        expect(execute).toHaveBeenCalledTimes(5);
        expect(vi.getTimerCount()).toBe(0);
    } finally {
        vi.useRealTimers();
    }
});

it('emits an initial empty query snapshot and stops after a failed read', async () => {
    vi.useFakeTimers();
    try {
        const db = new Firestore({ project_id: 'p' } as ServiceAccount);
        const execute = vi
            .fn()
            .mockResolvedValueOnce([])
            .mockRejectedValue(new Error('denied'));
        const next = vi.fn();
        const error = vi.fn();
        new Query(db, 'users', execute).onSnapshot(
            { pollIntervalMs: 10 },
            next,
            error
        );
        await vi.advanceTimersByTimeAsync(100);
        expect(next).toHaveBeenCalledOnce();
        expect(next.mock.calls[0]![0].docChanges()).toEqual([]);
        expect(error).toHaveBeenCalledOnce();
        expect(execute).toHaveBeenCalledTimes(2);
    } finally {
        vi.useRealTimers();
    }
});

it('supports snapshot cursors with stable document-ID tie breaking and raw fields', async () => {
    const execute = vi.fn().mockResolvedValue([]);
    const query = new Query(firestore, 'users', execute).orderBy(
        new FieldPath('a.b'),
        'desc'
    );
    const converter = {
        toFirestore: () => ({}),
        fromFirestore: () => ({ transformed: true })
    };
    const snapshot = new DocumentSnapshot(
        firestore.doc('users/a').withConverter(converter),
        { name: 'users/a', fields: { 'a.b': { integerValue: '20' } } }
    );
    for (const method of [
        'startAt',
        'startAfter',
        'endAt',
        'endBefore'
    ] as const) {
        await query[method](snapshot).get().then(firestoreData);
        const options = execute.mock.lastCall![1];
        const key = method.startsWith('start') ? 'start' : 'end';
        expect(options.orders).toEqual([
            { field: '`a.b`', direction: 'desc' },
            { field: '__name__', direction: 'desc' }
        ]);
        expect(options[key].values).toEqual([
            { integerValue: '20' },
            {
                referenceValue:
                    'projects/p/databases/(default)/documents/users/a'
            }
        ]);
    }
    expect(() =>
        query.startAfter(
            new DocumentSnapshot(firestore.doc('users/a'), undefined)
        )
    ).toThrow('existing');
    expect(() => query.startAfter(snapshot, 1)).toThrow(FirebaseEdgeError);
    expect(() =>
        new Query(firestore, 'users', execute)
            .orderBy('missing')
            .startAt(snapshot)
    ).toThrow('missing');
    const foreign = new Firestore({ project_id: 'p' } as ServiceAccount).doc(
        'users/a'
    );
    expect(() =>
        query.startAt(new DocumentSnapshot(foreign, { name: foreign.path }))
    ).toThrow('belong');
    await new Query(firestore, 'users', execute)
        .startAfter(snapshot)
        .get()
        .then(firestoreData);
    expect(execute.mock.lastCall![1].orders).toEqual([
        { field: '__name__', direction: 'asc' }
    ]);
});

it('returns the last documents in the original order and allows overriding the limit mode', async () => {
    const execute = vi
        .fn()
        .mockResolvedValue([
            { name: 'projects/p/databases/(default)/documents/users/z' },
            { name: 'projects/p/databases/(default)/documents/users/y' }
        ]);
    const query = new Query(firestore, 'users', execute);
    await expect(
        query.limitToLast(2).get().then(firestoreData)
    ).rejects.toThrow('orderBy');
    expect(() => query.limitToLast(0)).toThrow(FirebaseEdgeError);
    const snapshot = await query
        .orderBy('name')
        .limitToLast(2)
        .get()
        .then(firestoreData);
    expect(snapshot.docs.map((doc) => doc.id)).toEqual(['y', 'z']);
    expect(execute.mock.lastCall![1]).toMatchObject({ last: true, limit: 2 });
    await query
        .orderBy('name')
        .limitToLast(2)
        .limit(1)
        .get()
        .then(firestoreData);
    expect(execute.mock.lastCall![1]).toMatchObject({ last: false, limit: 1 });
});

it.each([0, -1, 1.5, NaN, Infinity, 2147483648])(
    'rejects invalid limits consistently in both modes: %s',
    (limit) => {
        const query = new Query(firestore, 'users', vi.fn());
        for (const method of ['limit', 'limitToLast'] as const)
            expect(() => query[method](limit)).toThrow(
                expect.objectContaining({
                    code: 'firestore/invalid-argument',
                    message: 'Query limit must be a positive 32-bit integer.'
                })
            );
    }
);

it('preserves the original query and converter when switching to last-limit mode', async () => {
    const execute = vi.fn().mockResolvedValue([]);
    const converter = { toFirestore: () => ({}), fromFirestore: () => ({}) };
    const original = new Query(firestore, 'users', execute)
        .withConverter(converter)
        .orderBy('name')
        .limit(3);
    const last = original.limitToLast(2);
    expect(last.converter).toBe(converter);
    await last.get().then(firestoreData);
    expect(execute.mock.lastCall![1]).toMatchObject({ last: true, limit: 2 });
    await original.get().then(firestoreData);
    expect(execute.mock.lastCall![1].limit).toBe(3);
    expect(execute.mock.lastCall![1].last).toBeUndefined();
});

it('returns converted query documents while preserving the converter across builders', async () => {
    const execute = vi.fn().mockResolvedValue([
        {
            name: 'projects/p/databases/(default)/documents/users/a',
            fields: { name: { stringValue: 'Alice' } }
        }
    ]);
    const converter = {
        toFirestore: (model: { label: string }) => ({ name: model.label }),
        fromFirestore: (
            snapshot: import('./query-document-snapshot.js').QueryDocumentSnapshot
        ) => ({ label: String(snapshot.get('name')) })
    };
    const query = new Query(firestore, 'users', execute)
        .withConverter(converter)
        .where('name', '==', 'Alice')
        .limit(1);
    const result = await query.get().then(firestoreData);
    expect(result.docs[0]!.data().label).toBe('Alice');
    expect(result.docs[0]!.ref.converter).toBe(converter);
    const raw = await query.withConverter(null).get().then(firestoreData);
    expect(raw.docs[0]!.data()).toEqual({ name: 'Alice' });
    expect(() => query.withConverter({} as never)).toThrow(FirebaseEdgeError);
});

it('streams snapshots with converters, forwards cancellation, and rejects limitToLast', async () => {
    const finished = vi.fn();
    let signal: AbortSignal | undefined;
    const stream = vi
        .spyOn(firestore, '_streamQuery')
        .mockImplementation(async function* (_path, _options, abort) {
            signal = abort;
            try {
                yield {
                    name: 'projects/p/databases/(default)/documents/users/a'
                };
                yield {
                    name: 'projects/p/databases/(default)/documents/users/b'
                };
            } finally {
                finished();
            }
        });
    const query = firestore.collection('users').withConverter({
        toFirestore: () => ({}),
        fromFirestore: () => 'converted'
    });
    const reader = query.stream().getReader();
    const first = await reader.read();
    expect(first.value?.data()).toBe('converted');
    expect(first.value?.id).toBe('a');
    await reader.cancel();
    expect(signal?.aborted).toBe(true);
    expect(finished).toHaveBeenCalled();
    expect(() => query.orderBy('name').limitToLast(2).stream()).toThrow(
        'cannot be streamed'
    );
    stream.mockRestore();
});

it('closes empty streams and forwards stream failures', async () => {
    const stream = vi
        .spyOn(firestore, '_streamQuery')
        .mockImplementation(async function* () {});
    const emptyReader = firestore.collection('users').stream().getReader();
    const empty = await emptyReader.read();
    expect(empty.done).toBe(true);
    stream.mockImplementation(async function* () {
        throw new Error('offline');
    });
    const reader = firestore.collection('users').stream().getReader();
    await expect(reader.read()).rejects.toThrow('offline');
    stream.mockRestore();
});

it('closes the upstream iterator if snapshot construction fails', async () => {
    const finished = vi.fn();
    const stream = vi
        .spyOn(firestore, '_streamQuery')
        .mockImplementation(async function* () {
            try {
                yield {
                    name: 'projects/p/databases/(default)/documents/invalid'
                };
            } finally {
                finished();
            }
        });
    const reader = firestore.collection('users').stream().getReader();
    await expect(reader.read()).rejects.toThrow('document');
    expect(finished).toHaveBeenCalled();
    stream.mockRestore();
});

it('accepts composite filters and literal FieldPaths and creates aggregate queries', async () => {
    const execute = vi.fn().mockResolvedValue([]);
    const query = new Query(firestore, 'users', execute);
    const filtered = query
        .where(
            Filter.or(Filter.where('a', '==', 1), Filter.where('b', '==', 2))
        )
        .where(new FieldPath('a.b'), '>', 0)
        .orderBy(new FieldPath('a.b'))
        .select(new FieldPath('a.b'));
    await filtered.get().then(firestoreData);
    expect(execute.mock.lastCall?.[1]).toMatchObject({
        compositeFilters: [{ op: 'OR' }, { field: '`a.b`' }],
        orders: [{ field: '`a.b`', direction: 'asc' }],
        fields: ['`a.b`']
    });
    const aggregate = vi
        .spyOn(firestore, '_aggregate')
        .mockResolvedValue({ n: 3 });
    const count = filtered.count();
    expect(count).toBeInstanceOf(AggregateQuery);
    await count.get().then(firestoreData);
    expect(aggregate.mock.lastCall?.[2].count).toBeInstanceOf(AggregateField);
    const result = await filtered
        .aggregate({ n: AggregateField.sum('price') })
        .get()
        .then(firestoreData);
    expect(result.data()).toEqual({ n: 3 });
    aggregate.mockRestore();
});

const firestore = new Firestore({ project_id: 'p' } as ServiceAccount);

it('chains all builders without mutating the base or sibling queries', async () => {
    const execute = vi.fn().mockResolvedValue([]);
    const base = new Query(firestore, 'users', execute);
    const input = { roles: ['admin'] };
    const filtered = base.where('profile', '==', input);
    input.roles.push('changed');
    const query = filtered
        .where('age', '>=', 18)
        .orderBy('age')
        .orderBy('name', 'desc')
        .limit(5)
        .offset(2)
        .select('name', 'profile.city');
    await query.get().then(firestoreData);
    expect(execute).toHaveBeenLastCalledWith('users', {
        filters: [
            {
                field: 'profile',
                operator: '==',
                value: {
                    mapValue: {
                        fields: {
                            roles: {
                                arrayValue: {
                                    values: [{ stringValue: 'admin' }]
                                }
                            }
                        }
                    }
                }
            },
            { field: 'age', operator: '>=', value: { integerValue: '18' } }
        ],
        orders: [
            { field: 'age', direction: 'asc' },
            { field: 'name', direction: 'desc' }
        ],
        limit: 5,
        offset: 2,
        fields: ['name', 'profile.city']
    });
    await base.get().then(firestoreData);
    expect(execute).toHaveBeenLastCalledWith('users', {});
    await filtered
        .limit(1)
        .limit(2)
        .offset(0)
        .select()
        .get()
        .then(firestoreData);
    expect(execute.mock.lastCall?.[1]).toMatchObject({
        limit: 2,
        offset: 0,
        fields: []
    });
    expect(execute.mock.lastCall?.[1].filters).toHaveLength(1);
});

it('returns query snapshots, reference metadata and decoded data without extra reads', async () => {
    const execute = vi.fn().mockResolvedValue([
        {
            name: 'projects/p/databases/(default)/documents/users/a',
            fields: { score: { integerValue: '3' } }
        },
        { name: 'projects/p/databases/(default)/documents/users/b' }
    ]);
    const query = new Query(firestore, 'users', execute);
    const snapshot = await query.get().then(firestoreData);
    expect(snapshot).toBeInstanceOf(QuerySnapshot);
    expect(snapshot.query).toBe(query);
    expect(snapshot).toMatchObject({ size: 2, empty: false });
    expect(snapshot.docs[0]).toMatchObject({
        id: 'a',
        exists: true,
        ref: { path: 'users/a' }
    });
    expect(snapshot.docs[0]!.data()).toEqual({ score: 3 });
    expect(snapshot.docs[1]!.data()).toEqual({});
    const context = { ids: [] as string[] };
    snapshot.forEach(function (this: typeof context, doc) {
        this.ids.push(doc.id);
    }, context);
    expect(context.ids).toEqual(['a', 'b']);
    expect(() => snapshot.forEach(null as never)).toThrow('callback');
    expect(execute).toHaveBeenCalledTimes(1);
});

it('returns empty snapshots and propagates execution failures', async () => {
    const execute = vi
        .fn()
        .mockResolvedValueOnce([])
        .mockRejectedValueOnce(new Error('permission denied'));
    const query = new Query(firestore, 'users', execute);
    const snapshot = await query.get().then(firestoreData);
    expect(snapshot).toMatchObject({ docs: [], size: 0, empty: true });
    const callback = vi.fn();
    snapshot.forEach(callback);
    expect(callback).not.toHaveBeenCalled();
    await expect(query.get().then(firestoreData)).rejects.toThrow(
        'permission denied'
    );
});

it.each([
    ['startAt', 'start', true],
    ['startAfter', 'start', false],
    ['endAt', 'end', false],
    ['endBefore', 'end', true]
] as const)('supports %s field-value cursors', async (method, key, before) => {
    const execute = vi.fn().mockResolvedValue([]);
    const query = new Query(firestore, 'users', execute)
        .orderBy('age')
        .orderBy('name');
    await query[method](20, 'A').get().then(firestoreData);
    expect(execute.mock.lastCall?.[1][key]).toEqual({
        before,
        values: [{ integerValue: '20' }, { stringValue: 'A' }]
    });
    expect(() => query[method]()).toThrow('Cursor');
    expect(() => query[method](1, 2, 3)).toThrow('Cursor');
    expect(() => query[method](20).orderBy('other')).toThrow('before cursor');
});

it('combines both cursor bounds', async () => {
    const execute = vi.fn().mockResolvedValue([]);
    await new Query(firestore, 'users', execute)
        .orderBy('age')
        .startAfter(18)
        .endAt(65)
        .get()
        .then(firestoreData);
    expect(execute.mock.lastCall?.[1]).toMatchObject({
        start: { before: false },
        end: { before: false }
    });
});

it('rejects invalid builders before executing', () => {
    const execute = vi.fn();
    const query = new Query(firestore, 'users', execute);
    for (const value of [-1, 1.5, NaN, Infinity, 2147483648]) {
        expect(() => query.limit(value)).toThrow('limit');
        expect(() => query.offset(value)).toThrow('offset');
    }
    expect(() => query.limit(0)).toThrow(FirebaseEdgeError);
    expect(() => query.orderBy('age', 'up' as never)).toThrow('direction');
    expect(() => query.where('age', 'bad' as never, 1)).toThrow('operator');
    expect(() => query.where('age', 'toString' as never, 1)).toThrow(
        'operator'
    );
    expect(() => query.where('age', '==', undefined)).toThrow('value');
    for (const operator of ['in', 'not-in', 'array-contains-any'] as const) {
        expect(() => query.where('age', operator, [])).toThrow('array');
        expect(() => query.where('age', operator, 'bad')).toThrow('array');
        expect(() => query.where('age', operator, Array(31).fill(1))).toThrow(
            'array'
        );
    }
    expect(() => query.where('age', 'not-in', Array(11).fill(1))).toThrow(
        FirebaseEdgeError
    );
    expect(() => query.startAt(1)).toThrow('orderBy');
    expect(() => query.select('')).toThrow('field');
    expect(execute).not.toHaveBeenCalled();
});
it('serializes collection and group queries for bundles without reversing limitToLast', () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const query = db
        .collection('users/a/posts')
        .orderBy('title')
        .limitToLast(2);
    expect(query._bundledQuery()).toMatchObject({
        parent: 'projects/p/databases/(default)/documents/users/a',
        limitType: 'LAST',
        structuredQuery: {
            from: [{ collectionId: 'posts' }],
            limit: 2,
            orderBy: [{ field: { fieldPath: 'title' }, direction: 'ASCENDING' }]
        }
    });
    expect(db.collectionGroup('posts')._bundledQuery()).toMatchObject({
        parent: 'projects/p/databases/(default)/documents',
        limitType: 'FIRST',
        structuredQuery: {
            from: [{ collectionId: 'posts', allDescendants: true }]
        }
    });
});
it('compares queries and snapshots and reports one-shot documents as added changes', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    vi.spyOn(db, '_query').mockResolvedValue([
        {
            name: 'projects/p/databases/(default)/documents/users/a',
            fields: { n: { integerValue: '1' } }
        }
    ]);
    const query = db.collection('users').where('a', '==', { b: 1, c: 2 });
    expect(
        query.isEqual(db.collection('users').where('a', '==', { c: 2, b: 1 }))
    ).toBe(true);
    expect(query.isEqual(query.limit(1))).toBe(false);
    expect(query.isEqual(null)).toBe(false);
    const first = await query.get().then(firestoreData);
    const second = await query.get().then(firestoreData);
    expect(first.isEqual(second)).toBe(true);
    expect(first.isEqual(null)).toBe(false);
    expect(first.docChanges()).toEqual([
        { type: 'added', doc: first.docs[0], oldIndex: -1, newIndex: 0 }
    ]);
    expect(new QuerySnapshot(query, []).docChanges()).toEqual([]);
});

it('explains queries with and without analysis and streams documents before metrics', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const metrics = { planSummary: { indexesUsed: [] }, executionStats: null };
    vi.spyOn(db, '_explainQuery').mockImplementation(async function* () {
        yield {
            document: {
                name: 'projects/p/databases/(default)/documents/users/a'
            },
            readTime: '2026-01-01T00:00:00Z'
        };
        yield { metrics };
    });
    const query = db.collection('users');
    const plan = await query.explain().then(firestoreData);
    expect(plan).toEqual({ metrics, snapshot: null });
    const analyzed = await query.explain({ analyze: true }).then(firestoreData);
    expect(analyzed.snapshot?.size).toBe(1);
    expect(analyzed.snapshot?.readTime.toString()).toBe(
        '2026-01-01T00:00:00.000000000Z'
    );
    const reader = query.explainStream({ analyze: true }).getReader();
    const first = await reader.read();
    const second = await reader.read();
    const last = await reader.read();
    expect(first.value?.document?.id).toBe('a');
    expect(second.value?.metrics).toBe(metrics);
    expect(last.done).toBe(true);
    await expect(
        query.explain({ analyze: 1 } as never).then(firestoreData)
    ).rejects.toThrow('options');
    expect(() => query.limitToLast(1).explainStream()).toThrow(
        'cannot be streamed'
    );
    await expect(
        query.limitToLast(1).explain().then(firestoreData)
    ).rejects.toThrow('orderBy');
    vi.spyOn(db, '_explainQuery').mockImplementation(async function* () {});
    await expect(query.explain().then(firestoreData)).rejects.toThrow(
        'No explain metrics'
    );
});

it('cancels explain streams and propagates failures', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    let signal: AbortSignal | undefined;
    let closed = false;
    vi.spyOn(db, '_explainQuery').mockImplementation(
        async function* (_path, _options, _explain, abort) {
            signal = abort;
            try {
                yield {
                    metrics: {
                        planSummary: { indexesUsed: [] },
                        executionStats: null
                    }
                };
            } finally {
                closed = true;
            }
        }
    );
    const reader = db.collection('users').explainStream().getReader();
    await reader.read();
    await reader.cancel();
    expect(signal?.aborted).toBe(true);
    expect(closed).toBe(true);
    vi.spyOn(db, '_explainQuery').mockImplementation(async function* () {
        throw new Error('offline');
    });
    await expect(
        db.collection('users').explainStream().getReader().read()
    ).rejects.toThrow('offline');
});
