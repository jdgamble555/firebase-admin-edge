import { firestoreData } from './firestore-results.js';

it('returns vector read and explain errors without nested result objects', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const failure = new Error('offline');
    vi.spyOn(db, '_query').mockRejectedValue(failure);
    const query = db
        .collection('users')
        .findNearest('vector', [1], { limit: 1, distanceMeasure: 'EUCLIDEAN' });
    const read = await query.get();
    expect(read).toEqual({ error: failure, data: null });
    const { error, data } = await query.explain({
        analyze: 'invalid'
    } as never);
    expect(error).toBeInstanceOf(Error);
    expect(data).toBeNull();
});
import { expect, it, vi } from 'vitest';
import {
    Firestore,
    VectorQuery,
    VectorQuerySnapshot,
    FieldPath,
    FieldValue
} from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

it('supports both vector query overloads and preserves filters and converters', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const execute = vi.spyOn(db, '_query').mockResolvedValue([
        {
            name: 'projects/p/databases/(default)/documents/users/a',
            fields: { label: { stringValue: 'Alice' } },
            readTime: '2026-01-01T00:00:00Z'
        }
    ]);
    const query = db
        .collection('users')
        .where('active', '==', true)
        .withConverter({
            toFirestore: (name: string) => ({ name }),
            fromFirestore: (doc) => String(doc.get('label'))
        });
    const vector = query.findNearest({
        vectorField: new FieldPath('a.b'),
        queryVector: [1, 2],
        limit: 3,
        distanceMeasure: 'COSINE',
        distanceResultField: new FieldPath('distance'),
        distanceThreshold: 0.5
    });
    expect(vector).toBeInstanceOf(VectorQuery);
    const snapshot = await vector.get().then(firestoreData);
    expect(snapshot).toBeInstanceOf(VectorQuerySnapshot);
    expect(snapshot.docs[0]!.data()).toBe('Alice');
    expect(snapshot.query).toBe(vector);
    expect(snapshot.size).toBe(1);
    expect(snapshot.empty).toBe(false);
    expect(execute.mock.lastCall?.[1]).toMatchObject({
        filters: [{ field: 'active' }],
        nearest: {
            vectorField: { fieldPath: '`a.b`' },
            limit: 3,
            distanceMeasure: 'COSINE',
            distanceResultField: 'distance',
            distanceThreshold: 0.5
        }
    });
    const options = {
        vectorField: 'embedding',
        queryVector: [1, 2],
        limit: 2,
        distanceMeasure: 'EUCLIDEAN' as const
    };
    const a = query.findNearest(options);
    const b = query.findNearest('embedding', FieldValue.vector([1, 2]), {
        limit: 2,
        distanceMeasure: 'EUCLIDEAN'
    });
    expect(a.isEqual(b)).toBe(true);
    expect(a.isEqual(vector)).toBe(false);
    expect(a.isEqual(null)).toBe(false);
    const other = await vector.get().then(firestoreData);
    expect(snapshot.isEqual(other)).toBe(true);
    expect(snapshot.isEqual(null)).toBe(false);
    const context = { names: [] as string[] };
    snapshot.forEach(function (this: typeof context, doc) {
        this.names.push(doc.data());
    }, context);
    expect(context.names).toEqual(['Alice']);
    expect(() => snapshot.forEach(null as never)).toThrow('callback');
    vi.spyOn(db, '_explainQuery').mockImplementation(async function* () {
        yield {
            metrics: { planSummary: { indexesUsed: [] }, executionStats: null }
        };
    });
    const explained = await vector
        .explain({ analyze: true })
        .then(firestoreData);
    expect(explained.snapshot).toBeInstanceOf(VectorQuerySnapshot);
    expect(explained.snapshot?.empty).toBe(true);
});
it.each([
    null,
    { limit: 0 },
    { limit: 1001 },
    { queryVector: [] },
    { queryVector: [NaN] },
    { distanceMeasure: 'bad' },
    { distanceThreshold: Infinity },
    { vectorField: '' },
    { distanceResultField: '' }
])('rejects invalid vector options', (changes) => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const config =
        changes === null
            ? null
            : {
                  vectorField: 'embedding',
                  queryVector: [1],
                  limit: 1,
                  distanceMeasure: 'DOT_PRODUCT',
                  ...changes
              };
    expect(() => db.collection('users').findNearest(config as never)).toThrow();
});

it('reports initial vector documents as added and handles empty results', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    vi.spyOn(db, '_query').mockResolvedValue([
        { name: 'projects/p/databases/(default)/documents/users/a', fields: {} }
    ]);
    const query = db.collection('users').findNearest('embedding', [1], {
        limit: 1,
        distanceMeasure: 'EUCLIDEAN'
    });
    const snapshot = await query.get().then(firestoreData);
    expect(snapshot.docChanges()).toEqual([
        { type: 'added', oldIndex: -1, newIndex: 0, doc: snapshot.docs[0] }
    ]);
    Object.assign(snapshot.docChanges()[0]!, { newIndex: 9 });
    expect(snapshot.docChanges()[0]!.newIndex).toBe(0);
    expect(
        new VectorQuerySnapshot(query, [], snapshot.readTime).docChanges()
    ).toEqual([]);
});
