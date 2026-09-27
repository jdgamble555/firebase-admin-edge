import { firestoreData } from './firestore-results.js';
import { afterEach, expect, it, vi } from 'vitest';
import { listenByPolling } from './snapshot-listener.js';
import { Firestore } from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
});

it('polls immediately, uses the default delay, skips unchanged values and unsubscribes', async () => {
    vi.useFakeTimers();
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const read = vi
        .fn()
        .mockResolvedValueOnce(1)
        .mockResolvedValueOnce(1)
        .mockResolvedValue(2);
    const next = vi.fn<(...args: any[]) => any>();
    const stop = listenByPolling(
        db,
        read,
        (current, previous) => (current === previous ? undefined : current),
        next
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(next).toHaveBeenCalledWith(1);
    await vi.advanceTimersByTimeAsync(4999);
    expect(read).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5001);
    expect(next.mock.calls).toEqual([[1], [2]]);
    stop();
    stop();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(10000);
    expect(read).toHaveBeenCalledTimes(3);
});

it('does not overlap reads and suppresses in-flight results after termination', async () => {
    vi.useFakeTimers();
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    let finish!: (value: number) => void;
    const read = vi.fn(
        () =>
            new Promise<number>((resolve) => {
                finish = resolve;
            })
    );
    const next = vi.fn<(...args: any[]) => any>();
    listenByPolling(db, read, (value) => value, { pollIntervalMs: 20 }, next);
    await vi.advanceTimersByTimeAsync(200);
    expect(read).toHaveBeenCalledTimes(1);
    await db.terminate().then(firestoreData);
    finish(1);
    await vi.advanceTimersByTimeAsync(100);
    expect(next).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
    expect(() => listenByPolling(db, read, (value) => value, next)).toThrow(
        'terminated'
    );
});

it('stops on read errors and callback errors and reports them once', async () => {
    vi.useFakeTimers();
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const error = vi.fn<(...args: any[]) => any>();
    const read = vi
        .fn<(...args: any[]) => any>()
        .mockRejectedValue(new Error('denied'));
    listenByPolling(
        db,
        read,
        (value) => value,
        vi.fn<(...args: any[]) => any>(),
        error,
        {
            pollIntervalMs: 10
        }
    );
    await vi.advanceTimersByTimeAsync(100);
    expect(error).toHaveBeenCalledOnce();
    expect(read).toHaveBeenCalledOnce();
    expect(error.mock.calls[0]![0].message).toBe('denied');
    listenByPolling(
        db,
        async () => 1,
        (value) => value,
        () => {
            throw new Error('callback');
        },
        error
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(error.mock.lastCall?.[0].message).toBe('callback');
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    listenByPolling(
        db,
        read,
        (value) => value,
        vi.fn<(...args: any[]) => any>()
    );
    listenByPolling(
        db,
        read,
        (value) => value,
        {},
        vi.fn<(...args: any[]) => any>(),
        () => {
            throw new Error('error callback');
        }
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(log).toHaveBeenCalledTimes(2);
    expect(vi.getTimerCount()).toBe(0);
});

it('can unsubscribe before the initial read and from inside the callback', async () => {
    vi.useFakeTimers();
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const read = vi.fn<(...args: any[]) => any>().mockResolvedValue(1);
    const stop = listenByPolling(
        db,
        read,
        (value) => value,
        vi.fn<(...args: any[]) => any>()
    );
    stop();
    await vi.advanceTimersByTimeAsync(0);
    expect(read).not.toHaveBeenCalled();
    const inside = listenByPolling(
        db,
        read,
        (value) => value,
        () => inside()
    );
    await vi.advanceTimersByTimeAsync(10000);
    expect(read).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
});

it('validates callbacks and poll intervals before registering', () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const register = vi.spyOn(db, '_registerSnapshotListener');
    for (const pollIntervalMs of [0, -1, NaN, Infinity, 1.5, 2147483648, '10'])
        expect(() =>
            listenByPolling(
                db,
                async () => 1,
                (value) => value,
                { pollIntervalMs } as never,
                vi.fn<(...args: any[]) => any>()
            )
        ).toThrow('pollIntervalMs');
    for (const invalid of [null, [], 'bad', 1])
        expect(() =>
            listenByPolling(
                db,
                async () => 1,
                (value) => value,
                invalid as never,
                vi.fn<(...args: any[]) => any>()
            )
        ).toThrow();
    expect(() =>
        listenByPolling(
            db,
            async () => 1,
            (value) => value,
            {}
        )
    ).toThrow();
    expect(() =>
        listenByPolling(
            db,
            async () => 1,
            (value) => value,
            vi.fn<(...args: any[]) => any>(),
            null as never
        )
    ).toThrow();
    expect(register).not.toHaveBeenCalled();
});
