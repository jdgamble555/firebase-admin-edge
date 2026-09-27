import { firestoreData } from './firestore-results.js';

it('returns document reads, writes, and validation failures as results', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const failure = new Error('denied');
    vi.spyOn(db, '_commit').mockRejectedValue(failure);
    vi.spyOn(db, '_listCollections').mockRejectedValue(failure);
    const ref = new DocumentReference(
        db,
        'users/a',
        vi.fn().mockRejectedValue(failure)
    );
    for (const operation of [
        () => ref.get(),
        () => ref.create({}),
        () => ref.set({}),
        () => ref.update({ n: 1 }),
        () => ref.delete(),
        () => ref.listCollections()
    ]) {
        const { error, data } = await operation();
        expect(error).toBe(failure);
        expect(data).toBeNull();
    }
    const { error, data } = await ref.update({});
    expect(error).toBeInstanceOf(FirebaseEdgeError);
    expect(data).toBeNull();
    const missing = new DocumentReference(
        db,
        'users/b',
        vi.fn().mockResolvedValue(undefined)
    );
    const { error: readError, data: snapshot } = await missing.get();
    expect(readError).toBeNull();
    expect(snapshot?.exists).toBe(false);
});
import { WriteResult } from './write-request.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it, vi } from 'vitest';
import { DocumentReference } from './document-reference.js';
import { Firestore } from './firestore.js';
import { FieldPath } from './field-path.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import { Timestamp } from './timestamp.js';

it('polls document changes, creation and deletion while preserving converters', async () => {
    vi.useFakeTimers();
    try {
        const db = new Firestore({ project_id: 'p' } as ServiceAccount);
        const execute = vi
            .fn()
            .mockResolvedValueOnce(undefined)
            .mockResolvedValueOnce({
                name: 'users/a',
                fields: { n: { integerValue: '1' } }
            })
            .mockResolvedValueOnce({
                name: 'users/a',
                fields: { n: { integerValue: '1' } }
            })
            .mockResolvedValueOnce({
                name: 'users/a',
                fields: { n: { integerValue: '2' } }
            })
            .mockResolvedValue(undefined);
        const ref = new DocumentReference(db, 'users/a', execute).withConverter(
            {
                toFirestore: () => ({}),
                fromFirestore: (snapshot) => ({ number: snapshot.get('n') })
            }
        );
        const next = vi.fn();
        const stop = ref.onSnapshot({ pollIntervalMs: 25 }, next);
        await vi.advanceTimersByTimeAsync(100);
        expect(next.mock.calls.map((call) => call[0].data())).toEqual([
            undefined,
            { number: 1 },
            { number: 2 },
            undefined
        ]);
        stop();
        await vi.advanceTimersByTimeAsync(100);
        expect(execute).toHaveBeenCalledTimes(5);
        const error = vi.fn();
        execute.mockRejectedValue(new Error('read failed'));
        ref.onSnapshot(next, error, { pollIntervalMs: 10 });
        await vi.advanceTimersByTimeAsync(100);
        expect(error).toHaveBeenCalledOnce();
        expect(vi.getTimerCount()).toBe(0);
    } finally {
        vi.useRealTimers();
    }
});

it('preserves and removes converters, and delegates subcollection listing', async () => {
    const collections = [{ path: 'users/a/posts' }];
    const firestore = {
        _trace: Firestore.prototype._trace,
        _listCollections: vi.fn().mockResolvedValue(collections)
    } as unknown as Firestore;
    const ref = new DocumentReference(firestore, 'users/a', vi.fn());
    const converter = {
        toFirestore: (value: { label: string }) => ({ name: value.label }),
        fromFirestore: () => ({ label: 'Alice' })
    };
    const converted = ref.withConverter(converter);
    expect(converted.converter).toBe(converter);
    expect(converted.isEqual(ref)).toBe(false);
    expect(converted.withConverter(null).isEqual(ref)).toBe(true);
    expect(converted._toFirestore({ label: 'A' })).toEqual({ name: 'A' });
    expect(() => ref.withConverter({} as never)).toThrow(FirebaseEdgeError);
    const listed = await converted.listCollections().then(firestoreData);
    expect(listed).toBe(collections);
    expect(firestore._listCollections).toHaveBeenCalledWith('users/a');
});

it('delegates document writes to a batch and returns its first write result', async () => {
    const result = new WriteResult(new Timestamp(0, 0));
    const batch = {
        create: vi.fn().mockReturnThis(),
        set: vi.fn().mockReturnThis(),
        update: vi.fn().mockReturnThis(),
        delete: vi.fn().mockReturnThis(),
        commit: vi.fn().mockResolvedValue({ error: null, data: [result] })
    };
    const firestore = {
        _trace: Firestore.prototype._trace,
        batch: vi.fn().mockReturnValue(batch)
    } as unknown as Firestore;
    const ref = new DocumentReference(firestore, 'users/a', vi.fn());
    const createResult = await ref.create({ n: 1 }).then(firestoreData);
    expect(createResult).toBe(result);
    expect(batch.create).toHaveBeenCalledWith(ref, { n: 1 });
    const setResult = await ref
        .set({ n: 2 }, { merge: true })
        .then(firestoreData);
    expect(setResult).toBe(result);
    expect(batch.set).toHaveBeenCalledWith(ref, { n: 2 }, { merge: true });
    const updateResult = await ref
        .update({ n: 3 }, { exists: true })
        .then(firestoreData);
    expect(updateResult).toBe(result);
    expect(batch.update).toHaveBeenCalledWith(ref, { n: 3 }, { exists: true });
    const deleteResult = await ref.delete().then(firestoreData);
    expect(deleteResult).toBe(result);
    expect(batch.delete).toHaveBeenCalledWith(ref, undefined);
    batch.commit.mockRejectedValue(new Error('denied'));
    await expect(ref.set({ n: 1 }).then(firestoreData)).rejects.toThrow(
        'denied'
    );
});

it('constructs a reference without executing a read', () => {
    const firestore = { _trace: Firestore.prototype._trace } as Firestore;
    const execute = vi.fn();
    const ref = new DocumentReference(
        firestore,
        'users/alice/posts/first',
        execute
    );
    expect(ref).toMatchObject({ id: 'first', path: 'users/alice/posts/first' });
    expect(ref.firestore).toBe(firestore);
    expect(execute).not.toHaveBeenCalled();
});

it.each([
    '',
    'users',
    '/users/a',
    'users/a/',
    'users//a',
    'users/.',
    'users/..',
    null
])('rejects invalid document path %s', (path) => {
    const execute = vi.fn();
    expect(
        () =>
            new DocumentReference(
                { _trace: Firestore.prototype._trace } as Firestore,
                path as string,
                execute
            )
    ).toThrow(FirebaseEdgeError);
    expect(execute).not.toHaveBeenCalled();
});

it.each(['users/alice', 'users/alice/posts/first'])(
    'resolves the parent of %s lazily through Firestore',
    (path) => {
        const parent = {
            path: path.slice(0, path.lastIndexOf('/')),
            withConverter: vi.fn().mockReturnThis()
        };
        const collection = vi.fn().mockReturnValue(parent);
        const firestore = { collection } as unknown as Firestore;
        const execute = vi.fn();
        const ref = new DocumentReference(firestore, path, execute);
        expect(collection).not.toHaveBeenCalled();
        expect(ref.parent).toBe(parent);
        expect(collection).toHaveBeenCalledWith(parent.path);
        expect(execute).not.toHaveBeenCalled();
    }
);

it('resolves immediate and nested relative collections through Firestore', () => {
    const child = { path: 'users/alice/posts' };
    const collection = vi.fn().mockReturnValue(child);
    const ref = new DocumentReference(
        { collection } as unknown as Firestore,
        'users/alice',
        vi.fn()
    );
    expect(ref.collection('posts')).toBe(child);
    expect(collection).toHaveBeenLastCalledWith('users/alice/posts');
    ref.collection('posts/first/comments');
    expect(collection).toHaveBeenLastCalledWith(
        'users/alice/posts/first/comments'
    );
    for (const path of [
        '',
        '/',
        '/posts',
        'posts/',
        'posts//comments',
        '.',
        '..',
        'posts/first',
        null
    ]) {
        expect(() => ref.collection(path as string)).toThrow(FirebaseEdgeError);
    }
    expect(collection).toHaveBeenCalledTimes(2);
});

it('reads a snapshot with this reference and fresh decoded data', async () => {
    const execute = vi.fn().mockResolvedValue({
        name: 'projects/p/databases/(default)/documents/users/alice',
        fields: {
            profile: {
                mapValue: { fields: { name: { stringValue: 'Alice' } } }
            }
        }
    });
    const ref = new DocumentReference(
        { _trace: Firestore.prototype._trace } as Firestore,
        'users/alice',
        execute
    );
    const snapshot = await ref.get().then(firestoreData);
    expect(execute).toHaveBeenCalledExactlyOnceWith('users/alice');
    expect(snapshot.id).toBe('alice');
    expect(snapshot.ref).toBe(ref);
    expect(snapshot.exists).toBe(true);
    const data = snapshot.data()!;
    (data.profile as { name: string }).name = 'Changed';
    expect(snapshot.data()).toEqual({ profile: { name: 'Alice' } });
});

it('distinguishes missing and empty documents and reads again on each get', async () => {
    const execute = vi
        .fn()
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce({ name: 'users/a' });
    const ref = new DocumentReference(
        { _trace: Firestore.prototype._trace } as Firestore,
        'users/a',
        execute
    );
    const missing = await ref.get().then(firestoreData);
    expect(missing).toMatchObject({ id: 'a', exists: false });
    expect(missing.ref).toBe(ref);
    expect(missing.data()).toBeUndefined();
    const empty = await ref.get().then(firestoreData);
    expect(empty.exists).toBe(true);
    expect(empty.data()).toEqual({});
    expect(execute).toHaveBeenCalledTimes(2);
});

it('propagates read failures', async () => {
    const error = new Error('permission denied');
    const ref = new DocumentReference(
        { _trace: Firestore.prototype._trace } as Firestore,
        'users/a',
        vi.fn().mockRejectedValue(error)
    );
    await expect(ref.get().then(firestoreData)).rejects.toBe(error);
});

it('compares the owning Firestore instance and document path', () => {
    const firestore = { _trace: Firestore.prototype._trace } as Firestore;
    const execute = vi.fn();
    const ref = new DocumentReference(firestore, 'users/a', execute);
    expect(ref.isEqual(ref)).toBe(true);
    expect(
        ref.isEqual(new DocumentReference(firestore, 'users/a', execute))
    ).toBe(true);
    expect(
        ref.isEqual(new DocumentReference(firestore, 'users/b', execute))
    ).toBe(false);
    expect(
        ref.isEqual(
            new DocumentReference(
                { _trace: Firestore.prototype._trace } as Firestore,
                'users/a',
                execute
            )
        )
    ).toBe(false);
    for (const other of [null, undefined, {}, { firestore, path: 'users/a' }]) {
        expect(ref.isEqual(other as DocumentReference)).toBe(false);
    }
    expect(execute).not.toHaveBeenCalled();
});
it('accepts variadic update fields with literal FieldPaths', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const commit = vi
        .spyOn(db, '_commit')
        .mockResolvedValue([new WriteResult(new Timestamp(1, 0))]);
    await db
        .doc('users/a')
        .update(new FieldPath('a.b'), 1, 'nested.count', 2)
        .then(firestoreData);
    expect(commit.mock.lastCall?.[0][0]).toMatchObject({
        fields: {
            'a.b': { integerValue: '1' },
            nested: { mapValue: { fields: { count: { integerValue: '2' } } } }
        },
        mask: ['`a.b`', 'nested.count']
    });
});

it('preserves converter argument counts for replacement and merge writes', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    vi.spyOn(db, '_commit').mockResolvedValue([
        new WriteResult(new Timestamp(0, 0))
    ]);
    const toFirestore = vi.fn((data: Record<string, unknown>) => data);
    const ref = db
        .doc('users/a')
        .withConverter({ toFirestore, fromFirestore: () => ({}) });
    await ref.set({ n: 1 }).then(firestoreData);
    expect(toFirestore.mock.calls[0]).toEqual([{ n: 1 }]);
    await ref.set({ n: 2 }, { merge: true }).then(firestoreData);
    expect(toFirestore.mock.calls[1]).toEqual([{ n: 2 }, { merge: true }]);
});
