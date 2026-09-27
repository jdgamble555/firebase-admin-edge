import { expect, it } from 'vitest';
import { firestoreData, firestoreResult } from './firestore-results.js';

it('returns data, including undefined, and unwraps successes', async () => {
    const result = await firestoreResult(async () => 42);
    expect(result).toEqual({ error: null, data: 42 });
    expect(firestoreData(result)).toBe(42);
    const empty = await firestoreResult(async () => {});
    expect(empty).toEqual({ error: null, data: undefined });
});

it('captures synchronous and asynchronous failures without losing identity', async () => {
    const failure = new Error('failed');
    const synchronous = await firestoreResult(() => {
        throw failure;
    });
    const asynchronous = await firestoreResult(async () => {
        throw failure;
    });
    expect(synchronous).toEqual({ error: failure, data: null });
    expect(asynchronous).toEqual(synchronous);
    expect(() => firestoreData(asynchronous)).toThrow(failure);
    const nonError = await firestoreResult(async () => {
        throw 'failed';
    });
    expect(nonError.error).toBeInstanceOf(Error);
    expect(nonError.data).toBeNull();
});
