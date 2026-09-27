import { firestoreData } from './firestore-results.js';

it('returns aggregate execution failures in both result methods', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const failure = new Error('offline');
    vi.spyOn(db, '_aggregate').mockRejectedValue(failure);
    const query = db.collection('users').count();
    const read = await query.get();
    const explain = await query.explain();
    expect(read).toEqual({ error: failure, data: null });
    expect(explain).toEqual(read);
});
import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it, vi } from 'vitest';
import {
    AggregateField,
    AggregateQuery,
    AggregateQuerySnapshot
} from './aggregate.js';
import { FieldPath } from './field-path.js';
import { Firestore } from './firestore.js';
import { Timestamp } from './timestamp.js';
import { aggregateReadTime, aggregateMetrics } from './aggregate.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import type { Query } from './query.js';
it('constructs and compares aggregate fields', () => {
    expect(AggregateField.count().type).toBe('AggregateField');
    expect(
        AggregateField.sum('price').isEqual(AggregateField.sum('price'))
    ).toBe(true);
    expect(
        AggregateField.sum('price').isEqual(AggregateField.average('price'))
    ).toBe(false);
    expect(AggregateField.count().isEqual(null as never)).toBe(false);
    expect(AggregateField.average(new FieldPath('a.b')).field).toBe('`a.b`');
    expect(() => AggregateField.sum('')).toThrow(FirebaseEdgeError);
});
it('executes aggregates, retains the query and returns fresh result data', async () => {
    const query = new Firestore({
        project_id: 'p'
    } as ServiceAccount).collection('users');
    const spec = { total: AggregateField.count() };
    const execute = vi.fn().mockResolvedValue({ total: 3, average: null });
    const aggregate = new AggregateQuery(query, spec, execute);
    spec.total = AggregateField.sum('x');
    const snapshot = await aggregate.get().then(firestoreData);
    expect(snapshot).toBeInstanceOf(AggregateQuerySnapshot);
    expect(aggregate.query).toBe(query);
    expect(snapshot.query).toBe(aggregate);
    expect(execute.mock.calls[0]![0].total.aggregateType).toBe('count');
    snapshot.data().total = 99;
    expect(snapshot.data()).toEqual({ total: 3, average: null });
    execute.mockRejectedValue(new Error('denied'));
    await expect(aggregate.get().then(firestoreData)).rejects.toThrow('denied');
});
it('rejects invalid aggregate specifications', () => {
    for (const spec of [
        null,
        {},
        { n: {} },
        Object.fromEntries(
            Array.from({ length: 6 }, (_, i) => [i, AggregateField.count()])
        )
    ])
        expect(
            () =>
                new AggregateQuery(
                    new Firestore({
                        project_id: 'p'
                    } as ServiceAccount).collection('users'),
                    spec as never,
                    vi.fn()
                )
        ).toThrow(FirebaseEdgeError);
});

it('accepts five aggregate fields at the supported boundary', async () => {
    const spec = Object.fromEntries(
        Array.from({ length: 5 }, (_, i) => [
            `count${i}`,
            AggregateField.count()
        ])
    );
    const execute = vi.fn().mockResolvedValue({});
    const query = new AggregateQuery(
        new Firestore({ project_id: 'p' } as ServiceAccount).collection(
            'users'
        ),
        spec,
        execute
    );
    await query.get().then(firestoreData);
    expect(execute).toHaveBeenCalledWith(spec);
});
it('compares aggregate definitions and results and retains server read times', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const first = db.collection('users').aggregate({
        count: AggregateField.count(),
        sum: AggregateField.sum('n')
    });
    const second = db.collection('users').aggregate({
        sum: AggregateField.sum('n'),
        count: AggregateField.count()
    });
    expect(first.isEqual(second)).toBe(true);
    expect(first.isEqual(db.collection('users').count())).toBe(false);
    expect(first.isEqual(null)).toBe(false);
    const data = { count: 2, sum: 5 };
    Object.defineProperty(data, aggregateReadTime, {
        value: new Timestamp(1, 2)
    });
    vi.spyOn(db, '_aggregate').mockResolvedValue(data);
    const a = await first.get().then(firestoreData);
    const b = await second.get().then(firestoreData);
    expect(a.isEqual(b)).toBe(true);
    expect(a.isEqual(null)).toBe(false);
    expect(a.readTime.isEqual(new Timestamp(1, 2))).toBe(true);
    const metrics = { planSummary: { indexesUsed: [] }, executionStats: null };
    Object.defineProperty(data, aggregateMetrics, { value: metrics });
    const plan = await first.explain().then(firestoreData);
    expect(plan).toEqual({ metrics, snapshot: null });
    const analyzed = await first.explain({ analyze: true }).then(firestoreData);
    expect(analyzed.snapshot?.data()).toEqual({ count: 2, sum: 5 });
    expect(analyzed.snapshot?.readTime.seconds).toBe(1);
    await expect(
        first.explain({ analyze: 'yes' } as never).then(firestoreData)
    ).rejects.toThrow('options');
    vi.spyOn(db, '_aggregate').mockResolvedValue({ count: 1 });
    await expect(first.explain().then(firestoreData)).rejects.toThrow(
        'No explain'
    );
});
