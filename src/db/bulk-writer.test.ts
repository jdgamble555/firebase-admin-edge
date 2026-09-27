import { firestoreData } from './firestore-results.js';
import { WriteResult } from './write-request.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it, vi } from 'vitest';
import { BulkWriter, BulkWriterError } from './bulk-writer.js';
import { Firestore } from './firestore.js';
import { Timestamp } from './timestamp.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
const account = { project_id: 'p' } as ServiceAccount;

it('resolves failed writes with BulkWriterError metadata and drains successfully', async () => {
    const db = new Firestore(account);
    vi.spyOn(db, '_batchWrite').mockRejectedValue(new Error('denied'));
    const writer = db.bulkWriter({ throttling: false });
    const { error, data } = await writer.create(db.doc('users/a'), {});
    expect(data).toBeNull();
    expect(error).toBeInstanceOf(BulkWriterError);
    expect(error).toMatchObject({
        code: 2,
        failedAttempts: 1,
        operationType: 'create'
    });
    const flushed = await writer.flush();
    const closed = await writer.close();
    expect(flushed).toEqual({ error: null, data: undefined });
    expect(closed).toEqual(flushed);
    const rejected = await writer.delete(db.doc('users/a'));
    expect(rejected.error).toBeInstanceOf(FirebaseEdgeError);
    expect(rejected.data).toBeNull();
});

it('uses converted application data for writes', async () => {
    const db = new Firestore(account);
    const commit = vi
        .spyOn(db, '_batchWrite')
        .mockImplementation(async (writes) =>
            writes.map(() => new WriteResult(new Timestamp(0, 0)))
        );
    const ref = db.doc('users/a').withConverter({
        toFirestore: (label: string) => ({ name: label }),
        fromFirestore: () => ''
    });
    const writer = db.bulkWriter();
    await writer.create(ref, 'Alice').then(firestoreData);
    await writer.set(ref, 'Bob', { merge: true }).then(firestoreData);
    await writer.close().then(firestoreData);
    expect(commit.mock.lastCall![0][0]!.fields).toEqual({
        name: { stringValue: 'Bob' }
    });
});
it('executes every operation and drains on flush/close', async () => {
    const db = new Firestore(account);
    const result = new WriteResult(new Timestamp(0, 0));
    const commit = vi.spyOn(db, '_batchWrite').mockResolvedValue([result]);
    const writer = new BulkWriter(db);
    const ref = db.doc('users/a');
    const handler = vi.fn();
    writer.onWriteResult(handler);
    const promises = [
        writer.create(ref, { n: 1 }).then(firestoreData),
        writer.set(ref, { n: 2 }).then(firestoreData),
        writer.update(ref, { n: 3 }).then(firestoreData),
        writer.delete(ref).then(firestoreData)
    ];
    await writer.flush().then(firestoreData);
    const allResult = await Promise.all(promises);
    expect(allResult).toEqual(Array(4).fill(result));
    expect(commit.mock.calls.map((call) => call[0][0]!.kind)).toEqual([
        'create',
        'set',
        'update',
        'delete'
    ]);
    expect(handler).toHaveBeenCalledTimes(4);
    expect(handler).toHaveBeenCalledWith(ref, result);
    await writer.close().then(firestoreData);
    await writer.close().then(firestoreData);
    await expect(writer.delete(ref).then(firestoreData)).rejects.toThrow(
        'closed'
    );
});
it('retries transient failures and exposes structured errors and attempt counts', async () => {
    const db = new Firestore(account);
    const result = new WriteResult(new Timestamp(0, 0));
    const cause = Object.assign(new Error('unavailable'), {
        code: 'firestore/unavailable'
    });
    const commit = vi
        .spyOn(db, '_batchWrite')
        .mockRejectedValueOnce(cause)
        .mockResolvedValueOnce([result]);
    const writer = new BulkWriter(db);
    const ref = db.doc('users/a');
    const setResult = await writer.set(ref, { n: 1 }).then(firestoreData);
    expect(setResult).toBe(result);
    expect(commit).toHaveBeenCalledTimes(2);
    commit.mockRejectedValue(
        Object.assign(new Error('denied'), {
            code: 'firestore/permission-denied'
        })
    );
    const errors: BulkWriterError[] = [];
    writer.onWriteError((error) => {
        errors.push(error);
        return error.failedAttempts < 2;
    });
    await expect(writer.delete(ref).then(firestoreData)).rejects.toMatchObject({
        code: 7,
        documentRef: ref,
        operationType: 'delete',
        failedAttempts: 2
    });
    expect(errors[0]).toBeInstanceOf(BulkWriterError);
    expect(errors[0]).toBeInstanceOf(Error);
    await writer.close().then(firestoreData);
});
it('rejects permanent failures without retry, preserves same-document order, and validates inputs', async () => {
    const db = new Firestore(account);
    const result = new WriteResult(new Timestamp(0, 0));
    const commit = vi
        .spyOn(db, '_batchWrite')
        .mockRejectedValueOnce(new Error('bad'))
        .mockResolvedValue([result]);
    const writer = new BulkWriter(db);
    const ref = db.doc('users/a');
    const first = writer.delete(ref).then(firestoreData);
    const second = writer.set(ref, { n: 2 }).then(firestoreData);
    await expect(first).rejects.toMatchObject({ code: 2, failedAttempts: 1 });
    await expect(second).resolves.toBe(result);
    await expect(
        writer.delete(new Firestore(account).doc('users/a')).then(firestoreData)
    ).rejects.toThrow('belong');
    expect(() => writer.onWriteError(null as never)).toThrow(FirebaseEdgeError);
    expect(() => writer.onWriteResult(null as never)).toThrow(
        FirebaseEdgeError
    );
    await expect(writer.update(ref, {}).then(firestoreData)).rejects.toThrow(
        FirebaseEdgeError
    );
    await writer.close().then(firestoreData);
});
it('validates throttling options', () => {
    const db = new Firestore(account);
    for (const options of [
        null,
        { throttling: null },
        { throttling: 'yes' },
        { throttling: { initialOpsPerSecond: 0 } },
        { throttling: { maxOpsPerSecond: Infinity } },
        { throttling: { initialOpsPerSecond: 10, maxOpsPerSecond: 5 } }
    ])
        expect(() => db.bulkWriter(options as never)).toThrow(
            FirebaseEdgeError
        );
});

it('paces writes, ramps after five minutes and respects the maximum rate', async () => {
    vi.useFakeTimers();
    try {
        const db = new Firestore(account);
        const commit = vi
            .spyOn(db, '_batchWrite')
            .mockImplementation(async (writes) =>
                writes.map(() => new WriteResult(new Timestamp(0, 0)))
            );
        const writer = db.bulkWriter({
            throttling: { initialOpsPerSecond: 2, maxOpsPerSecond: 3 }
        });
        const writes = [
            writer.set(db.doc('users/a'), {}).then(firestoreData),
            writer.set(db.doc('users/b'), {}).then(firestoreData),
            writer.set(db.doc('users/c'), {}).then(firestoreData)
        ];
        await vi.advanceTimersByTimeAsync(0);
        expect(commit).toHaveBeenCalledTimes(1);
        await vi.advanceTimersByTimeAsync(499);
        expect(commit).toHaveBeenCalledTimes(1);
        await vi.advanceTimersByTimeAsync(501);
        await Promise.all(writes);
        expect(commit).toHaveBeenCalledTimes(3);
        await vi.advanceTimersByTimeAsync(299000);
        const next = [
            writer.delete(db.doc('users/a')).then(firestoreData),
            writer.delete(db.doc('users/b')).then(firestoreData)
        ];
        await vi.advanceTimersByTimeAsync(333);
        expect(commit).toHaveBeenCalledTimes(4);
        await vi.advanceTimersByTimeAsync(1);
        await Promise.all(next);
        expect(commit).toHaveBeenCalledTimes(5);
        await writer.close().then(firestoreData);
    } finally {
        vi.useRealTimers();
    }
});

it('disables throttling without scheduling rate timers', async () => {
    vi.useFakeTimers();
    try {
        const db = new Firestore(account);
        const commit = vi
            .spyOn(db, '_batchWrite')
            .mockImplementation(async (writes) =>
                writes.map(() => new WriteResult(new Timestamp(0, 0)))
            );
        const writer = db.bulkWriter({ throttling: false });
        const writes = Array.from({ length: 20 }, (_, index) =>
            writer.set(db.doc(`users/${index}`), {}).then(firestoreData)
        );
        await Promise.all(writes);
        expect(commit).toHaveBeenCalledTimes(1);
        expect(vi.getTimerCount()).toBe(0);
        await writer.close().then(firestoreData);
    } finally {
        vi.useRealTimers();
    }
});
it('supports variadic updates', async () => {
    const db = new Firestore(account);
    const commit = vi
        .spyOn(db, '_batchWrite')
        .mockResolvedValue([new WriteResult(new Timestamp(1, 0))]);
    const writer = db.bulkWriter({ throttling: false });
    await writer.update(db.doc('users/a'), 'a', 1, 'b', 2).then(firestoreData);
    await writer.close().then(firestoreData);
    expect(commit.mock.lastCall?.[0][0]!.mask).toEqual(['a', 'b']);
});

it('packs 45 independent writes into three requests and keeps per-write results', async () => {
    const db = new Firestore(account);
    const commit = vi
        .spyOn(db, '_batchWrite')
        .mockImplementation(async (writes) =>
            writes.map(
                (write) =>
                    new WriteResult(
                        new Timestamp(Number(write.path.split('/')[1]), 0)
                    )
            )
        );
    const writer = db.bulkWriter();
    const callback = vi.fn();
    writer.onWriteResult(callback);
    const pending = Array.from({ length: 45 }, (_, index) =>
        writer.set(db.doc(`users/${index}`), { index }).then(firestoreData)
    );
    await writer.close().then(firestoreData);
    const results = await Promise.all(pending);
    expect(commit.mock.calls.map((call) => call[0].length)).toEqual([
        20, 20, 5
    ]);
    expect(results.map((result) => result.writeTime.seconds)).toEqual(
        Array.from({ length: 45 }, (_, index) => index)
    );
    expect(callback).toHaveBeenCalledTimes(45);
});

it('retries only failed writes and blocks subsequent writes to that document', async () => {
    const db = new Firestore(account);
    const result = new WriteResult(new Timestamp(1, 0));
    const unavailable = new FirebaseEdgeError({
        code: 'firestore/unavailable',
        message: 'retry'
    });
    const denied = new FirebaseEdgeError({
        code: 'firestore/permission-denied',
        message: 'denied'
    });
    const commit = vi
        .spyOn(db, '_batchWrite')
        .mockResolvedValueOnce([result, unavailable, denied])
        .mockImplementation(async (writes) => writes.map(() => result));
    const writer = db.bulkWriter({ throttling: false });
    const callback = vi.fn();
    writer.onWriteResult(callback);
    const first = writer.set(db.doc('users/a'), {}).then(firestoreData);
    const retry = writer.create(db.doc('users/b'), {}).then(firestoreData);
    const failure = writer.delete(db.doc('users/c')).then(firestoreData);
    const later = writer
        .update(db.doc('users/b'), { n: 2 })
        .then(firestoreData);
    const pending = Promise.allSettled([first, retry, failure, later]);
    await writer.close().then(firestoreData);
    const results = await pending;
    expect(results.map((result) => result.status)).toEqual([
        'fulfilled',
        'fulfilled',
        'rejected',
        'fulfilled'
    ]);
    expect(results[2]).toMatchObject({
        reason: { code: 7, failedAttempts: 1 }
    });
    expect(
        commit.mock.calls.map((call) =>
            call[0].map((write) => [write.path, write.kind])
        )
    ).toEqual([
        [
            ['users/a', 'set'],
            ['users/b', 'create'],
            ['users/c', 'delete']
        ],
        [['users/b', 'create']],
        [['users/b', 'update']]
    ]);
    expect(callback).toHaveBeenCalledTimes(3);
});

it('bounds requests in flight and drains queued batches after completions', async () => {
    const db = new Firestore(account);
    const completions: (() => void)[] = [];
    const commit = vi.spyOn(db, '_batchWrite').mockImplementation(
        (writes) =>
            new Promise((resolve) => {
                completions.push(() =>
                    resolve(
                        writes.map(() => new WriteResult(new Timestamp(0, 0)))
                    )
                );
            })
    );
    const writer = db.bulkWriter({ throttling: false });
    const writes = Array.from({ length: 220 }, (_, index) =>
        writer.delete(db.doc(`users/${index}`)).then(firestoreData)
    );
    await vi.waitFor(() => expect(commit).toHaveBeenCalledTimes(10));
    completions.shift()!();
    await vi.waitFor(() => expect(commit).toHaveBeenCalledTimes(11));
    for (const complete of completions) complete();
    await writer.close().then(firestoreData);
    await Promise.all(writes);
    expect(commit.mock.calls.every((call) => call[0].length === 20)).toBe(true);
});

it('isolates throwing callbacks and rejects malformed transport results without hanging', async () => {
    const db = new Firestore(account);
    const result = new WriteResult(new Timestamp(0, 0));
    const commit = vi
        .spyOn(db, '_batchWrite')
        .mockResolvedValue([result, result]);
    const writer = db.bulkWriter({ throttling: false });
    writer.onWriteResult((ref) => {
        if (ref.id === 'a') throw new Error('callback');
    });
    const results = Promise.allSettled([
        writer.set(db.doc('users/a'), {}).then(firestoreData),
        writer.set(db.doc('users/b'), {}).then(firestoreData)
    ]);
    await writer.flush().then(firestoreData);
    await expect(results).resolves.toEqual([
        {
            status: 'rejected',
            reason: expect.objectContaining({ message: 'callback' })
        },
        { status: 'fulfilled', value: result }
    ]);
    commit.mockResolvedValue([]);
    await expect(
        writer.delete(db.doc('users/c')).then(firestoreData)
    ).rejects.toMatchObject({
        code: 13
    });
    await writer.close().then(firestoreData);
});

it('retries internal delete errors but not internal set errors by default', async () => {
    const db = new Firestore(account);
    const result = new WriteResult(new Timestamp(0, 0));
    const failure = new FirebaseEdgeError({
        code: 'firestore/internal',
        message: 'transient'
    });
    const send = vi
        .spyOn(db, '_batchWrite')
        .mockResolvedValueOnce([failure])
        .mockResolvedValueOnce([result])
        .mockResolvedValueOnce([failure]);
    const writer = db.bulkWriter();
    await expect(
        writer.delete(db.doc('users/a')).then(firestoreData)
    ).resolves.toBe(result);
    await expect(
        writer.set(db.doc('users/a'), {}).then(firestoreData)
    ).rejects.toMatchObject({
        code: 13
    });
    await writer.close().then(firestoreData);
    expect(send).toHaveBeenCalledTimes(3);
});
