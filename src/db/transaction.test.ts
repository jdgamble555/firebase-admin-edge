import { firestoreData } from './firestore-results.js';
import { expect, it, vi } from 'vitest';
import { Transaction } from './transaction.js';
import { Firestore } from './firestore.js';
import { DocumentSnapshot } from './document-snapshot.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
const db = new Firestore({ project_id: 'p' } as ServiceAccount);

it.each([false, true])(
    'commits mutation pipelines with queued writes: %s',
    async (queueWrite) => {
        const firestore = new Firestore({ project_id: 'p' } as ServiceAccount);
        vi.spyOn(firestore, '_executePipeline').mockResolvedValue({
            results: [],
            executionTime: '2026-01-01T00:00:00Z'
        });
        const commit = vi.fn().mockResolvedValue([]);
        const transaction = new Transaction(
            firestore,
            vi.fn(),
            commit,
            false,
            'tx'
        );
        const { error } = await transaction.execute(
            firestore.pipeline().collection('users').delete()
        );
        expect(error).toBeNull();
        const read = await transaction.get(firestore.doc('users/a'));
        const bulkRead = await transaction.getAll(firestore.doc('users/a'));
        const pipelineRead = await transaction.execute(
            firestore.pipeline().collection('users')
        );
        for (const { error: readError, data } of [
            read,
            bulkRead,
            pipelineRead
        ]) {
            expect(readError).toBeInstanceOf(Error);
            expect(data).toBeNull();
        }
        if (queueWrite) {
            transaction.set(firestore.doc('audit/event'), { deleted: true });
        }

        await transaction._commit();

        expect(commit).toHaveBeenCalledOnce();
        expect(commit.mock.calls[0]![0]).toHaveLength(queueWrite ? 1 : 0);
    }
);

it('returns failed reads as results while preventing commit even when the error is handled', async () => {
    const failure = new Error('read failed');
    const commit = vi.fn();
    const tx = new Transaction(db, vi.fn().mockRejectedValue(failure), commit);
    const result = await tx.get(db.doc('users/a'));
    expect(result).toEqual({ error: failure, data: null });
    await expect(tx._commit()).rejects.toBe(failure);
    expect(commit).not.toHaveBeenCalled();
});

it('preserves converted read types and converts queued writes', async () => {
    const ref = db.doc('users/a').withConverter({
        toFirestore: (label: string) => ({ name: label }),
        fromFirestore: () => 'Alice'
    });
    const snapshot = new DocumentSnapshot(ref, { name: ref.path });
    const commit = vi.fn().mockResolvedValue([]);
    const tx = new Transaction(db, vi.fn().mockResolvedValue(snapshot), commit);
    const result = await tx.get(ref).then(firestoreData);
    expect(result.data()?.toUpperCase()).toBe('ALICE');
    tx.create(ref, 'Alice').set(ref, 'Bob');
    await tx._commit();
    expect(commit.mock.lastCall![0][1].fields).toEqual({
        name: { stringValue: 'Bob' }
    });
});
it('reads before writes and commits captured operations', async () => {
    const ref = db.doc('users/a');
    const snapshot = new DocumentSnapshot(ref, undefined);
    const read = vi.fn().mockResolvedValue(snapshot);
    const commit = vi.fn().mockResolvedValue([]);
    const tx = new Transaction(db, read, commit);
    const getResult = await tx.get(ref).then(firestoreData);
    expect(getResult).toBe(snapshot);
    expect(
        tx
            .create(ref, { n: 1 })
            .set(ref, { n: 2 })
            .update(ref, { n: 3 })
            .delete(ref)
    ).toBe(tx);
    await expect(tx.get(ref).then(firestoreData)).rejects.toThrow('precede');
    await tx._commit();
    expect(commit.mock.calls[0]![0]).toHaveLength(4);
    expect(() => tx.set(ref, {})).toThrow('closed');
    await expect(tx.get(ref).then(firestoreData)).rejects.toThrow('closed');
    await expect(tx._commit()).rejects.toThrow('closed');
    await expect(tx._commit()).rejects.toMatchObject({
        code: 'firestore/failed-precondition',
        name: 'FirebaseEdgeError'
    });
});
it('commits read-only transactions, rejects foreign reads and can close aborted attempts', async () => {
    const commit = vi.fn().mockResolvedValue([]);
    const tx = new Transaction(db, vi.fn(), commit);
    await expect(
        tx
            .get(
                new Firestore({ project_id: 'q' } as ServiceAccount).doc(
                    'users/a'
                )
            )
            .then(firestoreData)
    ).rejects.toThrow('belong');
    await tx._commit();
    expect(commit).toHaveBeenCalledWith([]);
    const aborted = new Transaction(db, vi.fn(), commit);
    aborted._close();
    expect(() => aborted.delete(db.doc('users/a'))).toThrow('closed');
});
it('does not commit if an outstanding read fails', async () => {
    const commit = vi.fn();
    const read = vi.fn().mockRejectedValue(new Error('read failed'));
    const tx = new Transaction(db, read, commit);
    void tx.get(db.doc('users/a'));
    await expect(tx._commit()).rejects.toThrow('read failed');
    expect(commit).not.toHaveBeenCalled();
});
it('rejects all write methods in a read-only transaction before queuing writes', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const commit = vi.fn().mockResolvedValue([]);
    const transaction = new Transaction(db, vi.fn(), commit, true);
    const ref = db.doc('users/a');
    expect(() => transaction.create(ref, {})).toThrow('Read-only');
    expect(() => transaction.set(ref, {})).toThrow('Read-only');
    expect(() => transaction.update(ref, { a: 1 })).toThrow('Read-only');
    expect(() => transaction.delete(ref)).toThrow('Read-only');
    await transaction._commit();
    expect(commit).toHaveBeenCalledWith([]);
});
it('reads queries, aggregates and projected bulk documents within the same transaction', async () => {
    const local = new Firestore({ project_id: 'p' } as ServiceAccount);
    const readQuery = vi
        .spyOn(local, '_query')
        .mockResolvedValue([
            { name: 'projects/p/databases/(default)/documents/users/a' }
        ]);
    const aggregate = vi
        .spyOn(local, '_aggregate')
        .mockResolvedValue({ count: 1 });
    const bulk = vi.spyOn(local, '_getAll').mockResolvedValue([]);
    const tx = new Transaction(
        local,
        vi.fn(),
        vi.fn().mockResolvedValue([]),
        false,
        'tx'
    );
    const query = local.collection('users').limit(1);
    const docs = await tx.get(query).then(firestoreData);
    expect(docs.size).toBe(1);
    expect(readQuery).toHaveBeenCalledWith('users', { limit: 1 }, 'tx');
    const totals = await tx.get(query.count()).then(firestoreData);
    expect(totals.data()).toEqual({ count: 1 });
    expect(aggregate.mock.lastCall?.[3]).toBe('tx');
    const ref = local.doc('users/a');
    await tx.getAll(ref, ref, { fieldMask: ['name'] }).then(firestoreData);
    expect(bulk).toHaveBeenCalledWith(
        [ref, ref, { fieldMask: ['name'] }],
        'tx'
    );
    await expect(
        tx.get(db.collection('users')).then(firestoreData)
    ).rejects.toThrow('belong');
    tx.update(ref, 'count', 1);
    await expect(tx.get(query).then(firestoreData)).rejects.toThrow('precede');
    await expect(tx.getAll(ref).then(firestoreData)).rejects.toThrow('precede');
    await tx._commit();
    await expect(tx.getAll(ref).then(firestoreData)).rejects.toThrow('closed');
});

it('waits for unawaited query reads and preserves their failures', async () => {
    const local = new Firestore({ project_id: 'p' } as ServiceAccount);
    const failure = new Error('query failed');
    vi.spyOn(local, '_query').mockRejectedValue(failure);
    const commit = vi.fn();
    const tx = new Transaction(local, vi.fn(), commit, false, 'tx');
    void tx.get(local.collection('users'));
    await expect(tx._commit()).rejects.toBe(failure);
    expect(commit).not.toHaveBeenCalled();
    const detached = new Transaction(local, vi.fn(), commit);
    await expect(
        detached.getAll(local.doc('users/a')).then(firestoreData)
    ).rejects.toThrow('server transaction');
    await expect(
        detached.get(local.collection('users')).then(firestoreData)
    ).rejects.toThrow('server transaction');
});

it('runs pipelines under the transaction and rejects invalid ownership or ordering', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    vi.spyOn(db, '_executePipeline').mockResolvedValue({
        results: [],
        executionTime: '2026-01-01T00:00:00Z'
    });
    const transaction = new Transaction(
        db,
        vi.fn(),
        vi.fn().mockResolvedValue([]),
        false,
        'tx'
    );
    const pipeline = db.pipeline().collection('users');
    const result = await transaction.execute(pipeline).then(firestoreData);
    expect(result.results).toEqual([]);
    expect(db._executePipeline).toHaveBeenCalledWith(
        expect.any(Object),
        'tx',
        undefined
    );
    await expect(
        transaction
            .execute(
                new Firestore({ project_id: 'p' } as ServiceAccount)
                    .pipeline()
                    .database()
            )
            .then(firestoreData)
    ).rejects.toThrow('belong');
    transaction.set(db.doc('users/a'), {});
    await expect(
        transaction.execute(pipeline).then(firestoreData)
    ).rejects.toThrow('before writes');
    transaction._close();
    await expect(
        transaction.execute(pipeline).then(firestoreData)
    ).rejects.toThrow();
});

it('rejects mutation pipelines in read-only transactions', async () => {
    const transaction = new Transaction(db, vi.fn(), vi.fn(), true, 'tx');
    await expect(
        transaction
            .execute(db.pipeline().collection('users').delete())
            .then(firestoreData)
    ).rejects.toThrow('Read-only');
});

it('preserves converter overload dispatch when setting transaction documents', () => {
    const toFirestore = vi.fn((data: Record<string, unknown>) => data);
    const ref = db
        .doc('users/a')
        .withConverter({ toFirestore, fromFirestore: () => ({}) });
    const transaction = new Transaction(db, vi.fn(), vi.fn());
    transaction.set(ref, { n: 1 });
    transaction.set(ref, { n: 2 }, { merge: true });
    expect(toFirestore.mock.calls).toEqual([
        [{ n: 1 }],
        [{ n: 2 }, { merge: true }]
    ]);
});
