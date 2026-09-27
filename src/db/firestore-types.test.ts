import { firestoreData } from './firestore-results.js';
import type {
    DocumentSnapshot,
    QuerySnapshot,
    Query,
    CollectionGroup,
    QueryPartition,
    AggregateQuerySnapshot,
    Transaction
} from './firestore.js';
import { expect, expectTypeOf, it, vi } from 'vitest';
import {
    Firestore,
    FieldValue,
    AggregateField,
    type DocumentReference,
    type SetOptions,
    type FirestoreDataConverter,
    type WithFieldValue,
    type PartialWithFieldValue,
    type UpdateData,
    type AggregateSpecData
} from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
it('accepts nested transforms and partial models and infers aggregate data', () => {
    type Model = { name: string; profile: { count: number; active: boolean } };
    const full: WithFieldValue<Model> = {
        name: 'A',
        profile: { count: FieldValue.increment(1), active: true }
    };
    const partial: PartialWithFieldValue<Model> = {
        profile: { count: FieldValue.maximum(2) }
    };
    const update: UpdateData<Model> = {
        'profile.count': FieldValue.increment(1)
    };
    expect(full.name).toBe('A');
    expect(partial.profile).toBeDefined();
    expect(update).toBeDefined();
    // @ts-expect-error unknown model property
    const invalid: UpdateData<Model> = { typo: 1 };
    void invalid;
    // @ts-expect-error required model properties cannot be omitted for full writes
    const incomplete: WithFieldValue<Model> = { name: 'A' };
    void incomplete;
    const spec = {
        count: AggregateField.count(),
        total: AggregateField.sum('n'),
        avg: AggregateField.average('n')
    };
    expectTypeOf<AggregateSpecData<typeof spec>>().toEqualTypeOf<{
        count: number;
        total: number;
        avg: number | null;
    }>();
});
it('carries both converter models through references and accepts partial merge writes', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const commit = vi.spyOn(db, '_commit').mockResolvedValue([]);
    type App = { label: string; count: number };
    type Stored = { name: string; n: number };
    function toFirestore(model: WithFieldValue<App>): WithFieldValue<Stored>;
    function toFirestore(
        model: PartialWithFieldValue<App>,
        options: SetOptions
    ): PartialWithFieldValue<Stored>;
    function toFirestore(
        model: PartialWithFieldValue<App>
    ): PartialWithFieldValue<Stored> {
        return {
            ...('label' in model ? { name: model.label } : {}),
            ...('count' in model ? { n: model.count } : {})
        };
    }
    const converter: FirestoreDataConverter<App, Stored> = {
        toFirestore,
        fromFirestore: () => ({ label: '', count: 0 })
    };
    expect(toFirestore({ label: 'A', count: 2 })).toEqual({ name: 'A', n: 2 });
    expect(
        toFirestore({ count: FieldValue.increment(1) }, { merge: true })
    ).toEqual({ n: FieldValue.increment(1) });
    const ref = db.doc('users/a').withConverter(converter);
    expectTypeOf(ref).toEqualTypeOf<DocumentReference<App, Stored>>();
    await db
        .doc('users/b')
        .withConverter<App>({
            toFirestore: (model) => model,
            fromFirestore: () => ({ label: '', count: 0 })
        })
        .set({ count: 1 }, { merge: true })
        .then(firestoreData);
    expect(commit).toHaveBeenCalled();
});

it('retains stored models across bulk reads, transactions, aggregates, and partitions', async () => {
    type App = { label: string };
    type Stored = {
        name: string;
        nested?: { count: number };
        byKey: Record<string, { count: number }>;
    };
    const converter: FirestoreDataConverter<App, Stored> = {
        toFirestore: () => ({ name: 'A', byKey: {} }),
        fromFirestore: () => ({ label: 'A' })
    };
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const ref = db.doc('users/a').withConverter(converter);
    const group = db.collectionGroup('users').withConverter(converter);
    expectTypeOf(group).toEqualTypeOf<CollectionGroup<App, Stored>>();
    const partitions = group.getPartitions(1);
    const partition = await partitions.next();
    if (partition.done) throw new Error('Missing partition');
    expectTypeOf(partition.value).toEqualTypeOf<QueryPartition<App, Stored>>();
    expectTypeOf(partition.value.toQuery()).toEqualTypeOf<Query<App, Stored>>();
    const update: UpdateData<Stored> = {
        'nested.count': 1,
        'byKey.some.count': 2
    };
    expect(update['nested.count']).toBe(1);
    if (false) {
        const transaction = null as unknown as Transaction;
        expectTypeOf(db.getAll(ref).then(firestoreData)).toEqualTypeOf<
            Promise<DocumentSnapshot<App, Stored>[]>
        >();
        expectTypeOf(transaction.getAll(ref).then(firestoreData)).toEqualTypeOf<
            Promise<DocumentSnapshot<App, Stored>[]>
        >();
        expectTypeOf(transaction.get(ref).then(firestoreData)).toEqualTypeOf<
            Promise<DocumentSnapshot<App, Stored>>
        >();
        expectTypeOf(transaction.get(group).then(firestoreData)).toEqualTypeOf<
            Promise<QuerySnapshot<App, Stored>>
        >();
        expectTypeOf(
            transaction.get(group.count()).then(firestoreData)
        ).toEqualTypeOf<
            Promise<
                AggregateQuerySnapshot<
                    { count: AggregateField<number> },
                    App,
                    Stored
                >
            >
        >();
        db.batch().update(ref, update);
        transaction.update(ref, update);
        db.bulkWriter().update(ref, update).then(firestoreData);
        // @ts-expect-error updates use the stored model, not the application model
        db.batch().update(ref, { label: 'A' });
        // @ts-expect-error unknown stored property
        transaction.update(ref, { typo: 1 });
        db.bulkWriter()
            // @ts-expect-error stored number field cannot be assigned a string
            .update(ref, { 'nested.count': 'wrong' })
            .then(firestoreData);
        // @ts-expect-error full writes require the application model
        db.batch().set(ref, {});
        db.batch().set(ref, {}, { merge: true });
        // @ts-expect-error nested numeric leaf remains typed
        const invalid: UpdateData<Stored> = { 'nested.count': 'wrong' };
        void invalid;
    }
});
