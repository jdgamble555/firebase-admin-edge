import { firestoreData } from './firestore-results.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it, vi } from 'vitest';
import { WriteBatch } from './write-batch.js';
import { Firestore } from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
const db = new Firestore({ project_id: 'p' } as ServiceAccount);

it('returns commit data and repeated-commit errors as results', async () => {
    const batch = new WriteBatch(db, vi.fn());
    const first = await batch.commit();
    expect(first).toEqual({ error: null, data: [] });
    const { error, data } = await batch.commit();
    expect(error).toBeInstanceOf(FirebaseEdgeError);
    expect(data).toBeNull();
});

it('applies converters to create/set including merge options, but not update', async () => {
    const converter = {
        toFirestore: vi.fn((value: { label: string }) => ({
            name: value.label
        })),
        fromFirestore: () => ({ label: '' })
    };
    const ref = db.doc('users/a').withConverter(converter);
    const execute = vi.fn().mockResolvedValue([]);
    const batch = new WriteBatch(db, execute);
    batch
        .create(ref, { label: 'A' })
        .set(ref, { label: 'B' }, { merge: true })
        .update(ref, { name: 'C' });
    await batch.commit().then(firestoreData);
    expect(converter.toFirestore).toHaveBeenCalledTimes(2);
    expect(converter.toFirestore).toHaveBeenLastCalledWith(
        { label: 'B' },
        { merge: true }
    );
    expect(
        execute.mock.lastCall![0].map(
            (write: { fields: unknown }) => write.fields
        )
    ).toEqual([
        { name: { stringValue: 'A' } },
        { name: { stringValue: 'B' } },
        { name: { stringValue: 'C' } }
    ]);
});
it('queues each operation, captures data, commits once and returns results', async () => {
    const execute = vi.fn().mockResolvedValue(['result']);
    const batch = new WriteBatch(db, execute);
    const ref = db.doc('users/a');
    const data = { n: 1 };
    expect(
        batch
            .create(ref, data)
            .set(ref, data, { merge: true })
            .update(ref, { n: 2 })
            .delete(ref)
    ).toBe(batch);
    data.n = 99;
    expect(execute).not.toHaveBeenCalled();
    const commitResult = await batch.commit().then(firestoreData);
    expect(commitResult).toEqual(['result']);
    expect(
        execute.mock.calls[0]![0].map((write: { kind: string }) => write.kind)
    ).toEqual(['create', 'set', 'update', 'delete']);
    expect(execute.mock.calls[0]![0][0].fields.n).toEqual({
        integerValue: '1'
    });
    expect(() => batch.delete(ref)).toThrow('committed');
    await expect(batch.commit().then(firestoreData)).rejects.toThrow(
        'committed'
    );
    await expect(batch.commit().then(firestoreData)).rejects.toMatchObject({
        code: 'firestore/failed-precondition',
        name: 'FirebaseEdgeError'
    });
});
it('handles empty batches, foreign references, failed commits and batch limits', async () => {
    const execute = vi.fn().mockRejectedValue(new Error('denied'));
    const commitResult2 = await new WriteBatch(db, execute)
        .commit()
        .then(firestoreData);
    expect(commitResult2).toEqual([]);
    expect(execute).not.toHaveBeenCalled();
    const batch = new WriteBatch(db, execute);
    const ref = db.doc('users/a');
    expect(() =>
        batch.delete(
            new Firestore({ project_id: 'p' } as ServiceAccount).doc('users/a')
        )
    ).toThrow('belong');
    expect(() => batch.delete({} as never)).toThrow(FirebaseEdgeError);
    for (let i = 0; i < 500; i++) batch.delete(ref);
    expect(() => batch.delete(ref)).toThrow('500');
    await expect(batch.commit().then(firestoreData)).rejects.toThrow('denied');
    await expect(batch.commit().then(firestoreData)).rejects.toThrow(
        'committed'
    );
});
it('supports variadic updates and preserves final preconditions', async () => {
    const local = new Firestore({ project_id: 'p' } as ServiceAccount);
    const execute = vi.fn().mockResolvedValue([]);
    const batch = new WriteBatch(local, execute);
    batch.update(local.doc('users/a'), 'count', 1, { exists: true });
    await batch.commit().then(firestoreData);
    expect(execute.mock.lastCall?.[0][0]).toMatchObject({
        fields: { count: { integerValue: '1' } },
        precondition: { exists: true }
    });
});
