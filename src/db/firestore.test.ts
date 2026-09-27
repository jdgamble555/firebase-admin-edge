import { firestoreData } from './firestore-results.js';

it('returns public orchestration failures and callback values as results', async () => {
    const db = new Firestore(account);
    const failure = new Error('denied');
    vi.spyOn(db, '_getAll').mockRejectedValue(failure);
    vi.spyOn(db, '_listCollections').mockRejectedValue(failure);
    const ref = db.doc('users/a');
    const all = await db.getAll(ref);
    const listed = await db.listCollections();
    expect(all).toEqual({ error: failure, data: null });
    expect(listed).toEqual(all);
    const transaction = await db.runTransaction(async () => 42);
    expect(transaction).toEqual({ error: null, data: 42 });
    const failed = await db.runTransaction(async () => {
        throw failure;
    });
    expect(failed).toEqual(all);
    const deleted = await db.recursiveDelete(null as never);
    expect(deleted.error).toBeInstanceOf(Error);
    expect(deleted.data).toBeNull();
    const terminated = await db.terminate();
    expect(terminated).toEqual({ error: null, data: undefined });
});

it('isolates shared caches by service account and avoids caching expired tokens', async () => {
    const cached = new Map<string, unknown>();
    const cache = {
        getCache: vi.fn((key: string) => cached.get(key)) as never,
        setCache: vi.fn((key: string, value: unknown) => {
            cached.set(key, value);
        })
    };
    for (const email of [
        'first@example.com',
        'second@example.com',
        'first@example.com'
    ]) {
        const db = new Firestore(
            { ...account, client_email: email },
            undefined,
            undefined,
            cache
        );
        const { error } = await db.doc('users/a').get();
        expect(error).toBeNull();
    }
    expect(getToken).toHaveBeenCalledTimes(2);
    expect(cached.size).toBe(2);
    vi.mocked(getToken).mockResolvedValue({
        error: null,
        data: { ...token, expires_in: 30 }
    });
    const shortCache = { getCache: vi.fn(), setCache: vi.fn() };
    const db = new Firestore(account, undefined, undefined, shortCache);
    const { error } = await db.doc('users/a').get();
    expect(error).toBeNull();
    expect(shortCache.setCache).not.toHaveBeenCalled();
});
import { streamPipeline } from './firestore-endpoints.js';
import { executePipeline } from './firestore-endpoints.js';
import { WriteResult } from './write-request.js';
import { beforeEach, expect, it, vi } from 'vitest';
import {
    QueryDocumentSnapshot,
    DocumentSnapshot
} from './document-snapshot.js';
import { Bytes } from './bytes.js';

it('deregisters polling listeners and stops registered listeners on termination', async () => {
    const db = new Firestore(account);
    const removed = vi.fn();
    const active = vi.fn();
    const unregister = db._registerSnapshotListener(removed);
    unregister();
    unregister();
    db._registerSnapshotListener(active);
    await db.terminate().then(firestoreData);
    await db.terminate().then(firestoreData);
    expect(removed).not.toHaveBeenCalled();
    expect(active).toHaveBeenCalledOnce();
    expect(() => db._registerSnapshotListener(vi.fn())).toThrow('terminated');
});

it('constructs raw JSON snapshots locally with metadata and decoded references', () => {
    const transport = vi.fn();
    const db = new Firestore(account, 'custom', transport);
    db.settings({ useBigInt: true });
    const name = `projects/${account.project_id}/databases/custom/documents/users/a`;
    const time = '2026-01-01T00:00:00.123456789Z';
    const raw = {
        name,
        fields: {
            count: { integerValue: '9223372036854775807' },
            bytes: { bytesValue: 'AQI=' },
            ref: { referenceValue: name },
            nested: { mapValue: { fields: { active: { booleanValue: true } } } }
        },
        createTime: time,
        updateTime: time
    };
    const snapshot = db.snapshot_(raw, time, 'json');
    expect(snapshot).toBeInstanceOf(QueryDocumentSnapshot);
    expect(snapshot.exists).toBe(true);
    expect(snapshot.ref.firestore).toBe(db);
    expect(snapshot.readTime.nanoseconds).toBe(123456789);
    expect(snapshot.createTime?.isEqual(snapshot.readTime)).toBe(true);
    expect(snapshot.updateTime?.isEqual(snapshot.readTime)).toBe(true);
    expect(snapshot.data()).toEqual({
        count: 9223372036854775807n,
        bytes: Bytes.fromUint8Array(new Uint8Array([1, 2])),
        ref: expect.any(DocumentReference),
        nested: { active: true }
    });
    expect(
        (snapshot.get('ref') as DocumentReference).isEqual(db.doc('users/a'))
    ).toBe(true);
    raw.fields.nested.mapValue.fields.active.booleanValue = false;
    expect(snapshot.get('nested.active')).toBe(true);
    expect(getToken).not.toHaveBeenCalled();
    expect(transport).not.toHaveBeenCalled();
});

it('constructs protobuf and missing snapshots with no request', () => {
    const db = new Firestore(account);
    const name = `projects/${account.project_id}/databases/(default)/documents/users/a`;
    const time = { seconds: '5', nanos: 6 };
    const snapshot = db.snapshot_(
        {
            name,
            fields: {
                bytes: { bytesValue: new Uint8Array([1, 2]) },
                at: { timestampValue: time }
            },
            createTime: time,
            updateTime: time
        },
        time
    );
    expect(snapshot.get('at')).toEqual(new Timestamp(5, 6));
    expect(snapshot.get('bytes')).toEqual(Bytes.fromBase64String('AQI='));
    const missing = db.snapshot_(name, time);
    expect(missing).toBeInstanceOf(DocumentSnapshot);
    expect(missing).not.toBeInstanceOf(QueryDocumentSnapshot);
    expect(missing.exists).toBe(false);
    expect(missing.data()).toBeUndefined();
    expect(missing.createTime).toBeUndefined();
    expect(missing.updateTime).toBeUndefined();
    expect(missing.readTime).toEqual(new Timestamp(5, 6));
    expect(db.snapshot_(name).readTime).toBeInstanceOf(Timestamp);
    expect(
        db
            .snapshot_(name, '1970-01-01T00:00:05.000000006Z', 'json')
            .isEqual(missing)
    ).toBe(true);
    expect(getToken).not.toHaveBeenCalled();
});

it('validates snapshot encodings, document paths, metadata and lifecycle', async () => {
    const db = new Firestore(account);
    expect(() => db.snapshot_('users/a', {}, 'ascii' as never)).toThrow(
        'encoding'
    );
    for (const name of [
        'users/a',
        'projects/p/databases/db/documents/users',
        'projects/p/databases/db/documents/'
    ])
        expect(() => db.snapshot_(name, {})).toThrow();
    expect(() =>
        db.snapshot_({ name: 'projects/p/databases/db/documents/users/a' }, {})
    ).toThrow('timestamp');
    expect(() => db.snapshot_(null as never, {})).toThrow();
    await db.terminate().then(firestoreData);
    expect(() =>
        db.snapshot_('projects/p/databases/db/documents/users/a', {})
    ).toThrow('terminated');
});
import {
    Firestore,
    DocumentReference,
    CollectionReference
} from './firestore.js';
import { getToken } from '../auth/google-oauth.js';
import {
    getDocument,
    runQuery,
    commitWrites,
    batchWrite,
    beginTransaction,
    rollbackTransaction,
    runAggregate,
    batchGetDocuments,
    listCollectionIds,
    listDocumentPaths,
    streamQuery,
    partitionQuery,
    configureFirestoreFetch,
    streamQueryRows
} from './firestore-endpoints.js';
import { WriteBatch } from './write-batch.js';
import { Transaction } from './transaction.js';
import { BulkWriter } from './bulk-writer.js';
import { Timestamp } from './timestamp.js';
import { AggregateField } from './aggregate.js';
import { FieldPath } from './field-path.js';

it('configures identity, REST destination and serialization once before use', async () => {
    const db = new Firestore(account);
    const transport = vi.fn();
    vi.mocked(configureFirestoreFetch).mockReturnValue(transport);
    db.settings({
        projectId: 'other',
        databaseId: 'db',
        host: 'localhost:8080',
        ssl: false,
        preferRest: true,
        ignoreUndefinedProperties: true,
        credentials: { client_email: 'a@b', private_key: 'key' }
    });
    expect(db.toJSON()).toEqual({ projectId: 'other' });
    expect(JSON.parse(JSON.stringify(db))).toEqual({ projectId: 'other' });
    expect(db._ignoreUndefinedProperties).toBe(true);
    await db.doc('users/a').get().then(firestoreData);
    expect(getDocument).toHaveBeenCalledWith(
        'other',
        'db',
        'users/a',
        'token',
        transport
    );
    expect(getToken).toHaveBeenCalledWith(
        expect.objectContaining({
            project_id: 'other',
            client_email: 'a@b',
            private_key: 'key'
        }),
        transport
    );
    expect(() => db.settings({})).toThrow('before');
    const used = new Firestore(account);
    used.collection('users');
    expect(() => used.settings({})).toThrow('before');
});

it.each([
    null,
    [],
    { databaseId: 'a/b' },
    { projectId: '' },
    { credentials: { client_email: '', private_key: '' } },
    { ssl: 'no' },
    { preferRest: false },
    { unknown: true }
])(
    'rejects invalid settings without consuming the configuration opportunity: %j',
    (settings) => {
        const db = new Firestore(account);
        expect(() => db.settings(settings as never)).toThrow(FirebaseEdgeError);
        db.settings({});
    }
);

it('creates bundles and delegates partition queries with the configured database', async () => {
    const db = new Firestore(account, 'db');
    expect(db.bundle('example').build()).toBeInstanceOf(Uint8Array);
    vi.mocked(partitionQuery).mockResolvedValue(['posts/a']);
    const paths = await db._partitionQuery('posts', 4);
    expect(paths).toEqual(['posts/a']);
    expect(partitionQuery).toHaveBeenCalledWith(
        'project',
        'db',
        'posts',
        4,
        'token',
        undefined
    );
});

it('terminates idempotently and rejects existing references, queries and new operations', async () => {
    const db = new Firestore(account);
    const ref = db.doc('users/a');
    const query = db.collection('users');
    await db.terminate().then(firestoreData);
    await db.terminate().then(firestoreData);
    await expect(ref.get().then(firestoreData)).rejects.toThrow('terminated');
    await expect(query.get().then(firestoreData)).rejects.toThrow('terminated');
    expect(() => db.doc('users/b')).toThrow('terminated');
    expect(() => db.batch()).toThrow('terminated');
    expect(() => db.bulkWriter()).toThrow('terminated');
    expect(() => db.bundle()).toThrow('terminated');
    expect(() => db.settings({})).toThrow('before');
    expect(getToken).not.toHaveBeenCalled();
});

it('aborts active query streams when terminated', async () => {
    const db = new Firestore(account);
    let signal: AbortSignal | undefined;
    vi.mocked(streamQuery).mockImplementation(async function* (...args) {
        signal = args[6];
        await new Promise<void>((_resolve, reject) =>
            signal!.addEventListener('abort', () => reject(signal!.reason), {
                once: true
            })
        );
    });
    const reader = db.collection('users').stream().getReader();
    const read = reader.read();
    const rejected = expect(read).rejects.toThrow('terminated');
    await vi.waitFor(() => expect(signal).toBeDefined());
    await db.terminate().then(firestoreData);
    await rejected;
    expect(signal?.aborted).toBe(true);
});

it('supports read-only transactions with historical read times and no commit or retry', async () => {
    const db = new Firestore(account);
    const ref = db.doc('users/a');
    const readTime = new Timestamp(1700000000, 123456000);
    vi.mocked(beginTransaction).mockResolvedValue('read-only');
    const value = await db
        .runTransaction(
            async (transaction) => {
                const doc = await transaction.get(ref).then(firestoreData);
                return doc.exists;
            },
            { readOnly: true, readTime }
        )
        .then(firestoreData);
    expect(value).toBe(true);
    expect(beginTransaction).toHaveBeenCalledWith(
        'project',
        '(default)',
        'token',
        undefined,
        { readOnly: true, readTime }
    );
    expect(rollbackTransaction).toHaveBeenCalledWith(
        'project',
        '(default)',
        'read-only',
        'token',
        undefined
    );
    expect(commitWrites).not.toHaveBeenCalled();
    vi.mocked(beginTransaction).mockClear();
    const aborted = Object.assign(new Error('abort'), {
        code: 'firestore/aborted'
    });
    await expect(
        db
            .runTransaction(
                async () => {
                    throw aborted;
                },
                { readOnly: true }
            )
            .then(firestoreData)
    ).rejects.toBe(aborted);
    expect(beginTransaction).toHaveBeenCalledOnce();
    await expect(
        db
            .runTransaction(
                async (transaction) => {
                    transaction.set(ref, {});
                },
                { readOnly: true }
            )
            .then(firestoreData)
    ).rejects.toThrow('Read-only');
});

it.each([
    null,
    { readOnly: 'yes' },
    { readOnly: true, maxAttempts: 2 },
    { readOnly: true, readTime: 'yesterday' },
    { readTime: new Timestamp(0, 0) }
])('validates transaction options: %j', async (options) => {
    await expect(
        new Firestore(account)
            .runTransaction(async () => 1, options as never)
            .then(firestoreData)
    ).rejects.toThrow('options');
    expect(beginTransaction).not.toHaveBeenCalled();
});

it('owns the default recursive deletion writer but leaves supplied writers usable', async () => {
    const db = new Firestore(account);
    vi.mocked(listCollectionIds).mockResolvedValue([]);
    vi.mocked(batchWrite).mockResolvedValue([new WriteResult(Timestamp.now())]);
    const writer = db.bulkWriter({ throttling: false });
    const close = vi.spyOn(writer, 'close');
    const factory = vi.spyOn(db, 'bulkWriter').mockReturnValue(writer);
    await db.recursiveDelete(db.doc('users/a')).then(firestoreData);
    expect(close).toHaveBeenCalledOnce();
    factory.mockRestore();
    const supplied = db.bulkWriter({ throttling: false });
    await db.recursiveDelete(db.doc('users/b'), supplied).then(firestoreData);
    await supplied.set(db.doc('users/c'), {}).then(firestoreData);
    await supplied.close().then(firestoreData);
    const other = new Firestore(account);
    await expect(
        db.recursiveDelete(other.doc('users/a')).then(firestoreData)
    ).rejects.toThrow('belong');
    await expect(
        db
            .recursiveDelete(db.doc('users/a'), other.bulkWriter())
            .then(firestoreData)
    ).rejects.toThrow('belong');
    await expect(
        db.recursiveDelete({} as never).then(firestoreData)
    ).rejects.toThrow('belong');
});

it('executes collection groups from the database root and guards invalid IDs', async () => {
    const db = new Firestore(account);
    vi.mocked(runQuery).mockResolvedValue([]);
    await db.collectionGroup('posts').get().then(firestoreData);
    expect(runQuery).toHaveBeenCalledWith(
        'project',
        '(default)',
        'posts',
        { allDescendants: true },
        'token',
        undefined
    );
    for (const id of ['', 'a/b', '.', '..', null])
        expect(() => db.collectionGroup(id as string)).toThrow(
            FirebaseEdgeError
        );
});

it('getAll preserves reference identity, conversion, order and field masks', async () => {
    const db = new Firestore(account);
    const converter = {
        toFirestore: (name: string) => ({ name }),
        fromFirestore: () => 'Alice'
    };
    const a = db.doc('users/a').withConverter(converter);
    const b = db.doc('users/b').withConverter(converter);
    vi.mocked(batchGetDocuments).mockResolvedValue([
        { name: 'users/a' },
        undefined
    ]);
    const result = await db
        .getAll(a, b, { fieldMask: [new FieldPath('a.b')] })
        .then(firestoreData);
    expect(result[0]!.ref).toBe(a);
    expect(result[0]!.data()).toBe('Alice');
    expect(result[1]!.exists).toBe(false);
    expect(batchGetDocuments).toHaveBeenCalledWith(
        'project',
        '(default)',
        ['users/a', 'users/b'],
        'token',
        undefined,
        ['`a.b`']
    );
    await expect(db.getAll().then(firestoreData)).rejects.toThrow(
        FirebaseEdgeError
    );
    await expect(
        db.getAll(new Firestore(account).doc('users/a')).then(firestoreData)
    ).rejects.toThrow('belong');
    await expect(
        db.getAll(a, { fieldMask: 'bad' as never }).then(firestoreData)
    ).rejects.toThrow('fieldMask');
});

it('lists root/nested collections and documents using the configured database', async () => {
    const db = new Firestore(account, 'custom');
    vi.mocked(listCollectionIds).mockResolvedValue(['posts']);
    const root = await db.listCollections().then(firestoreData);
    expect(root[0]!.path).toBe('posts');
    const nested = await db
        .doc('users/a')
        .listCollections()
        .then(firestoreData);
    expect(nested[0]!.path).toBe('users/a/posts');
    expect(listCollectionIds).toHaveBeenLastCalledWith(
        'project',
        'custom',
        'users/a',
        'token',
        undefined
    );
    vi.mocked(listDocumentPaths).mockResolvedValue(['users/a']);
    const refs = await db
        .collection('users')
        .listDocuments()
        .then(firestoreData);
    expect(refs[0]!.path).toBe('users/a');
    expect(listDocumentPaths).toHaveBeenCalledWith(
        'project',
        'custom',
        'users',
        'token',
        undefined
    );
});

it('streams with shared credentials and cancels before a request if already aborted', async () => {
    const db = new Firestore(account);
    const document = {
        name: 'projects/project/databases/(default)/documents/users/a'
    };
    vi.mocked(streamQuery).mockImplementation(async function* () {
        yield document;
    });
    const reader = db.collection('users').stream().getReader();
    const first = await reader.read();
    expect(first.value?.id).toBe('a');
    const next = await reader.read();
    expect(next.done).toBe(true);
    expect(streamQuery).toHaveBeenCalledWith(
        'project',
        '(default)',
        'users',
        {},
        'token',
        undefined,
        expect.any(AbortSignal)
    );
    const abort = new AbortController();
    abort.abort();
    await expect(
        db._streamQuery('users', {}, abort.signal).next()
    ).rejects.toBe(abort.signal.reason);
});

it('exposes write factories and delegates document writes to authenticated commits', async () => {
    const fetchFn = vi.fn();
    const db = new Firestore(account, 'custom', fetchFn);
    expect(db.batch()).toBeInstanceOf(WriteBatch);
    expect(db.bulkWriter()).toBeInstanceOf(BulkWriter);
    const result = new WriteResult(new Timestamp(0, 0));
    vi.mocked(commitWrites).mockResolvedValue([result]);
    const ref = db.doc('users/a');
    const createResult = await ref.create({ n: 1 }).then(firestoreData);
    expect(createResult).toBe(result);
    const setResult = await ref
        .set({ n: 2 }, { merge: true })
        .then(firestoreData);
    expect(setResult).toBe(result);
    const updateResult = await ref.update({ n: 3 }).then(firestoreData);
    expect(updateResult).toBe(result);
    const deleteResult = await ref.delete().then(firestoreData);
    expect(deleteResult).toBe(result);
    expect(commitWrites).toHaveBeenLastCalledWith(
        'project',
        'custom',
        [expect.objectContaining({ path: 'users/a', kind: 'delete' })],
        'token',
        fetchFn
    );
    vi.mocked(getToken).mockResolvedValueOnce({
        data: null,
        error: new FirebaseEdgeError({ message: 'token failed' })
    });
    await expect(ref.delete().then(firestoreData)).rejects.toThrow(
        'token failed'
    );
});

it('runs and commits a transaction, forwarding its ID on reads', async () => {
    const db = new Firestore(account);
    vi.mocked(beginTransaction).mockResolvedValue('tx');
    vi.mocked(commitWrites).mockResolvedValue([]);
    const value = await db
        .runTransaction(async (tx) => {
            expect(tx).toBeInstanceOf(Transaction);
            const ref = db.doc('users/a');
            const snap = await tx.get(ref).then(firestoreData);
            tx.update(ref, { active: true });
            return snap.id;
        })
        .then(firestoreData);
    expect(value).toBe('a');
    expect(getDocument).toHaveBeenCalledWith(
        'project',
        '(default)',
        'users/a',
        'token',
        undefined,
        'tx'
    );
    expect(commitWrites).toHaveBeenCalledWith(
        'project',
        '(default)',
        expect.any(Array),
        'token',
        undefined,
        'tx'
    );
    expect(rollbackTransaction).not.toHaveBeenCalled();
});

it('retries aborted attempts and closes old transactions, but preserves other callback failures', async () => {
    const db = new Firestore(account);
    vi.mocked(beginTransaction).mockResolvedValue('tx');
    const aborted = new FirebaseEdgeError({
        code: 'firestore/aborted',
        message: 'conflict'
    });
    vi.mocked(commitWrites)
        .mockRejectedValueOnce(aborted)
        .mockResolvedValue([]);
    const attempts: Transaction[] = [];
    const runTransactionResult = await db
        .runTransaction(async (tx) => {
            attempts.push(tx);
            return 'ok';
        })
        .then(firestoreData);
    expect(runTransactionResult).toBe('ok');
    expect(attempts).toHaveLength(2);
    expect(rollbackTransaction).toHaveBeenCalledTimes(1);
    await expect(
        attempts[0]!.get(db.doc('users/a')).then(firestoreData)
    ).rejects.toThrow('closed');
    const failure = new Error('callback');
    vi.mocked(rollbackTransaction).mockRejectedValueOnce(new Error('rollback'));
    await expect(
        db
            .runTransaction(async () => {
                throw failure;
            })
            .then(firestoreData)
    ).rejects.toBe(failure);
    vi.mocked(commitWrites).mockRejectedValue(aborted);
    await expect(
        db.runTransaction(async () => 1, { maxAttempts: 1 }).then(firestoreData)
    ).rejects.toBe(aborted);
    await expect(
        db.runTransaction(async () => 1, { maxAttempts: 0 }).then(firestoreData)
    ).rejects.toThrow('maxAttempts');
    await expect(
        db.runTransaction(null as never).then(firestoreData)
    ).rejects.toThrow(FirebaseEdgeError);
});

it('delegates server aggregates with shared credentials', async () => {
    const db = new Firestore(account);
    vi.mocked(runAggregate).mockResolvedValue({ count: 4 });
    const result = await db
        .collection('users')
        .limit(2)
        .count()
        .get()
        .then(firestoreData);
    expect(result.data()).toEqual({ count: 4 });
    expect(runAggregate).toHaveBeenCalledWith(
        'project',
        '(default)',
        'users',
        { limit: 2 },
        { count: expect.any(AggregateField) },
        'token',
        undefined
    );
});
import type { ServiceAccount } from '../auth/firebase-types.js';
import { FirebaseEdgeError } from '../auth/errors.js';

vi.mock('../auth/google-oauth.js');
vi.mock('./firestore-endpoints.js');
const account = { project_id: 'project' } as ServiceAccount;
const token = {
    access_token: 'token',
    expires_in: 3600,
    token_type: 'Bearer' as const,
    scope: 'datastore',
    id_token: ''
};
beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(getToken).mockResolvedValue({ data: token, error: null });
    vi.mocked(getDocument).mockResolvedValue({
        name: 'users/alice',
        fields: { name: { stringValue: 'Alice' } }
    });
});

it('executes collection queries with the configured credentials and transport', async () => {
    const fetchFn = vi.fn();
    const cache = {
        getCache: vi.fn().mockReturnValue(token),
        setCache: vi.fn()
    };
    vi.mocked(runQuery).mockResolvedValueOnce([]);
    const db = new Firestore(account, 'custom', fetchFn, cache, 'query-token');
    const getResult = await db
        .collection('users')
        .limit(2)
        .get()
        .then(firestoreData);
    expect(getResult.empty).toBe(true);
    expect(runQuery).toHaveBeenCalledWith(
        'project',
        'custom',
        'users',
        { limit: 2 },
        'token',
        fetchFn
    );
    expect(cache.getCache).toHaveBeenCalledWith(
        `query-token:firestore:${account.client_email}`
    );
    expect(getToken).not.toHaveBeenCalled();
});

it('does not execute queries when authentication fails', async () => {
    const error = new FirebaseEdgeError({ message: 'bad token' });
    vi.mocked(getToken).mockResolvedValueOnce({ data: null, error });
    await expect(
        new Firestore(account).collection('users').get().then(firestoreData)
    ).rejects.toBe(error);
    expect(runQuery).not.toHaveBeenCalled();
});

it('returns DocumentReference instances through factories and parent navigation', () => {
    const db = new Firestore(account);
    const ref = db.doc('users/alice');
    expect(ref).toBeInstanceOf(DocumentReference);
    expect(db.collection('users').doc('alice').isEqual(ref)).toBe(true);
    expect(ref.firestore).toBe(db);
    expect(ref.parent).toBeInstanceOf(CollectionReference);
    expect(ref.parent.path).toBe('users');
    expect(ref.parent.parent).toBeNull();
    const posts = ref.collection('posts');
    expect(posts.parent).toBeInstanceOf(DocumentReference);
    expect(posts.parent!.isEqual(ref)).toBe(true);
    expect(posts.doc('first').parent.parent!.isEqual(ref)).toBe(true);
    expect(getToken).not.toHaveBeenCalled();
    expect(getDocument).not.toHaveBeenCalled();
});

it('keeps document reads and subcollection queries on the configured database', async () => {
    const fetchFn = vi.fn();
    const db = new Firestore(account, 'custom', fetchFn);
    const ref = db.doc('users/alice');
    await ref.collection('posts').doc('first').get().then(firestoreData);
    expect(getDocument).toHaveBeenCalledWith(
        'project',
        'custom',
        'users/alice/posts/first',
        'token',
        fetchFn
    );
    vi.mocked(runQuery).mockResolvedValueOnce([]);
    await ref.collection('posts').limit(1).get().then(firestoreData);
    expect(runQuery).toHaveBeenCalledWith(
        'project',
        'custom',
        'users/alice/posts',
        { limit: 1 },
        'token',
        fetchFn
    );
});

it('uses DocumentReference instances in query snapshots', async () => {
    vi.mocked(runQuery).mockResolvedValueOnce([
        { name: 'projects/project/databases/(default)/documents/users/alice' }
    ]);
    const db = new Firestore(account);
    const snapshot = await db.collection('users').get().then(firestoreData);
    const ref = snapshot.docs[0]!.ref;
    expect(ref).toBeInstanceOf(DocumentReference);
    expect(ref.isEqual(db.doc('users/alice'))).toBe(true);
    expect(ref.parent.path).toBe('users');
    const getResult2 = await ref.get().then(firestoreData);
    expect(getResult2.ref).toBe(ref);
});

it('reads through collection().doc().get() with snapshot metadata and fresh data', async () => {
    const fetchFn = vi.fn();
    const db = new Firestore(account, 'custom', fetchFn);
    const collection = db.collection('users');
    expect(collection).toMatchObject({ id: 'users', path: 'users' });
    const ref = collection.doc('alice');
    const snapshot = await ref.get().then(firestoreData);
    expect(snapshot).toMatchObject({ id: 'alice', exists: true, ref });
    expect(snapshot.data()).toEqual({ name: 'Alice' });
    expect(snapshot.data()).not.toBe(snapshot.data());
    expect(getToken).toHaveBeenCalledWith(account, fetchFn);
    expect(getDocument).toHaveBeenCalledWith(
        'project',
        'custom',
        'users/alice',
        'token',
        fetchFn
    );
});

it('supports direct and nested document paths with the default database', async () => {
    const db = new Firestore(account);
    expect(db.collection('users/a/posts').doc('p').path).toBe(
        'users/a/posts/p'
    );
    expect(db.collection('users').doc('a/posts/p').id).toBe('p');
    await db.doc('users/a').get().then(firestoreData);
    expect(getDocument).toHaveBeenCalledWith(
        'project',
        '(default)',
        'users/a',
        'token',
        undefined
    );
});

it('distinguishes missing and empty documents', async () => {
    const ref = new Firestore(account).doc('users/a');
    vi.mocked(getDocument).mockResolvedValueOnce(undefined);
    const missing = await ref.get().then(firestoreData);
    expect(missing.exists).toBe(false);
    expect(missing.data()).toBeUndefined();
    vi.mocked(getDocument).mockResolvedValueOnce({ name: 'users/a' });
    const empty = await ref.get().then(firestoreData);
    expect(empty.exists).toBe(true);
    expect(empty.data()).toEqual({});
});

it.each([
    '',
    '/users/a',
    'users//a',
    'users/a/',
    'users/..',
    'users/.',
    'users'
])('rejects invalid document path %s before fetching', (path) => {
    expect(() => new Firestore(account).doc(path)).toThrow(FirebaseEdgeError);
    expect(getToken).not.toHaveBeenCalled();
});

it('guards constructor and collection paths', () => {
    expect(() => new Firestore({} as ServiceAccount)).toThrow('project_id');
    expect(() => new Firestore(account, '')).toThrow('database');
    expect(() => new Firestore(account, 'a/b')).toThrow('database');
    const db = new Firestore(account);
    expect(() => db.collection('users/a')).toThrow('collection');
    expect(() => db.collection('users').doc('')).toThrow(FirebaseEdgeError);
    expect(() => db.collection('users').doc('/a')).toThrow(FirebaseEdgeError);
    expect(() => db.doc(null as unknown as string)).toThrow(FirebaseEdgeError);
});

it('uses the same cache key for reads and writes with a millisecond TTL', async () => {
    const cache = { getCache: vi.fn(), setCache: vi.fn() };
    const db = new Firestore(
        account,
        undefined,
        undefined,
        cache,
        'custom-token'
    );
    await db.doc('users/a').get().then(firestoreData);
    expect(cache.getCache).toHaveBeenCalledWith(
        `custom-token:firestore:${account.client_email}`
    );
    expect(cache.setCache).toHaveBeenCalledWith(
        `custom-token:firestore:${account.client_email}`,
        token,
        3540000
    );
    cache.getCache.mockResolvedValue(token);
    await db.doc('users/a').get().then(firestoreData);
    expect(getToken).toHaveBeenCalledTimes(1);
});

it('uses the default cache key and refreshes an empty cached token', async () => {
    const cache = { getCache: vi.fn().mockReturnValue({}), setCache: vi.fn() };
    await new Firestore(account, undefined, undefined, cache)
        .doc('users/a')
        .get()
        .then(firestoreData);
    expect(cache.setCache).toHaveBeenCalledWith(
        `__cache:firestore:${account.client_email}`,
        token,
        3540000
    );
});

it('propagates token and endpoint errors', async () => {
    const ref = new Firestore(account).doc('users/a');
    const error = new FirebaseEdgeError({ message: 'credentials failed' });
    vi.mocked(getToken).mockResolvedValueOnce({ data: null, error });
    await expect(ref.get().then(firestoreData)).rejects.toBe(error);
    expect(getDocument).not.toHaveBeenCalled();
    vi.mocked(getToken).mockResolvedValueOnce({
        data: { ...token, access_token: '' },
        error: null
    });
    await expect(ref.get().then(firestoreData)).rejects.toThrow(
        'No service account'
    );
    vi.mocked(getDocument).mockRejectedValueOnce(error);
    await expect(ref.get().then(firestoreData)).rejects.toBe(error);
});
it('stops before dispatch if terminated while obtaining credentials', async () => {
    let resolve!: (value: { data: typeof token; error: null }) => void;
    vi.mocked(getToken).mockImplementation(
        () =>
            new Promise((done) => {
                resolve = done;
            })
    );
    const db = new Firestore(account);
    const read = db.doc('users/a').get().then(firestoreData);
    const rejected = expect(read).rejects.toThrow('terminated');
    await vi.waitFor(() => expect(resolve).toBeDefined());
    await db.terminate().then(firestoreData);
    resolve({ data: token, error: null });
    await rejected;
    expect(getDocument).not.toHaveBeenCalled();
});

it('isolates cached tokens when settings replace credentials', async () => {
    const cache = {
        getCache: vi.fn().mockReturnValue(undefined),
        setCache: vi.fn()
    };
    const db = new Firestore(account, undefined, undefined, cache, 'auth');
    db.settings({
        credentials: { client_email: 'other@example.com', private_key: 'key' }
    });
    await db.doc('users/a').get().then(firestoreData);
    expect(cache.getCache).toHaveBeenCalledWith(
        'auth:firestore:other@example.com'
    );
});
it('exposes project/database identity and decodes resource references', () => {
    const db = new Firestore(account, 'custom');
    expect(db.projectId).toBe('project');
    expect(db.databaseId).toBe('custom');
    const ref = db._reference(
        'projects/project/databases/custom/documents/users/a'
    );
    expect(ref.firestore).toBe(db);
    expect(ref.path).toBe('users/a');
    const external = db._reference(
        'projects/other/databases/archive/documents/users/a'
    );
    expect(external.firestore.projectId).toBe('other');
    expect(external.firestore.databaseId).toBe('archive');
    expect(() => db._reference('bad')).toThrow('Invalid document reference');
});

it('coordinates transaction bulk, query and aggregate reads through endpoint functions', async () => {
    const db = new Firestore(account);
    vi.mocked(beginTransaction).mockResolvedValue('tx-read');
    vi.mocked(commitWrites).mockResolvedValue([]);
    vi.mocked(batchGetDocuments).mockResolvedValue([undefined]);
    vi.mocked(runQuery).mockResolvedValue([]);
    vi.mocked(runAggregate).mockResolvedValue({ count: 0 });
    await db
        .runTransaction(async (tx) => {
            await tx
                .getAll(db.doc('users/a'), { fieldMask: ['name'] })
                .then(firestoreData);
            await tx.get(db.collection('users')).then(firestoreData);
            await tx.get(db.collection('users').count()).then(firestoreData);
        })
        .then(firestoreData);
    expect(batchGetDocuments).toHaveBeenCalledWith(
        'project',
        '(default)',
        ['users/a'],
        'token',
        undefined,
        ['name'],
        'tx-read'
    );
    expect(runQuery).toHaveBeenCalledWith(
        'project',
        '(default)',
        'users',
        {},
        'token',
        undefined,
        'tx-read'
    );
    expect(runAggregate).toHaveBeenCalledWith(
        'project',
        '(default)',
        'users',
        {},
        expect.any(Object),
        'token',
        undefined,
        'tx-read'
    );
});
it('coordinates explain streams and forwards abort signals', async () => {
    const db = new Firestore(account);
    let signal: AbortSignal | undefined;
    vi.mocked(streamQueryRows).mockImplementation(async function* (...args) {
        signal = args[6];
        yield {
            metrics: { planSummary: { indexesUsed: [] }, executionStats: null }
        };
    });
    const result = await db.collection('users').explain().then(firestoreData);
    expect(result.snapshot).toBeNull();
    expect(streamQueryRows).toHaveBeenCalledWith(
        'project',
        '(default)',
        'users',
        {},
        'token',
        undefined,
        expect.any(AbortSignal),
        {}
    );
    expect(signal).toBeDefined();
});

it('delegates independent bulk writes with credentials and rejects after termination', async () => {
    const transport = vi.fn();
    const db = new Firestore(account, undefined, transport);
    const writes = [{ path: 'users/a', kind: 'delete' as const }];
    const outcomes = [new WriteResult(new Timestamp(0, 0))];
    vi.mocked(batchWrite).mockResolvedValue(outcomes);
    await expect(db._batchWrite(writes)).resolves.toBe(outcomes);
    expect(batchWrite).toHaveBeenCalledWith(
        account.project_id,
        '(default)',
        writes,
        token.access_token,
        transport
    );
    await db.terminate().then(firestoreData);
    await expect(db._batchWrite(writes)).rejects.toThrow('terminated');
});

it('retries transient transaction initialization and callback failures', async () => {
    const db = new Firestore(account);
    vi.mocked(beginTransaction)
        .mockRejectedValueOnce(
            new FirebaseEdgeError({
                code: 'firestore/unavailable',
                message: 'retry'
            })
        )
        .mockResolvedValue('tx');
    const callback = vi
        .fn()
        .mockRejectedValueOnce(
            new FirebaseEdgeError({
                code: 'firestore/internal',
                message: 'retry'
            })
        )
        .mockResolvedValue(42);
    const result = await db.runTransaction(callback).then(firestoreData);
    expect(result).toBe(42);
    expect(beginTransaction).toHaveBeenCalledTimes(3);
    expect(callback).toHaveBeenCalledTimes(2);
});
it('exposes implicit ordering configuration before query construction', () => {
    const db = new Firestore(account);
    expect(db.alwaysUseImplicitOrderBy).toBe(false);
    db.settings({ alwaysUseImplicitOrderBy: true });
    expect(db.alwaysUseImplicitOrderBy).toBe(true);
    const query = db.collection('users').where('age', '>', 0);
    expect(query._bundledQuery()).toMatchObject({
        structuredQuery: {
            orderBy: [
                { field: { fieldPath: 'age' }, direction: 'ASCENDING' },
                { field: { fieldPath: '__name__' }, direction: 'ASCENDING' }
            ]
        }
    });
});

it('coordinates authenticated pipeline execution and termination', async () => {
    const db = new Firestore(account);
    vi.mocked(executePipeline).mockResolvedValue({
        results: [],
        executionTime: '2026-01-01T00:00:00Z'
    });
    const result = await db
        .pipeline()
        .collection('users')
        .execute()
        .then(firestoreData);
    expect(result.results).toEqual([]);
    expect(executePipeline).toHaveBeenCalledWith(
        'project',
        '(default)',
        expect.any(Object),
        'token',
        undefined,
        undefined,
        undefined
    );
    await db.terminate().then(firestoreData);
    expect(() => db.pipeline()).toThrow('terminated');
});

it('coordinates pipeline stream authentication and cancellation', async () => {
    const db = new Firestore(account);
    vi.mocked(streamPipeline).mockImplementation(async function* () {
        yield { fields: {} };
    });
    const stream = db._streamPipeline({}, new AbortController().signal);
    const first = await stream.next();
    expect(first.value).toEqual({ fields: {} });
    expect(streamPipeline).toHaveBeenCalledWith(
        'project',
        '(default)',
        {},
        'token',
        undefined,
        expect.any(AbortSignal),
        undefined
    );
    const signal = vi.mocked(streamPipeline).mock.calls[0]![5]!;
    await db.terminate().then(firestoreData);
    expect(signal.aborted).toBe(true);
    await stream.return(undefined);
});
