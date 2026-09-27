import { expect, it } from 'vitest';
import { FirebaseEdgeError } from '../auth/errors.js';
import {
    storageData,
    storageResult,
    storageUnsupported
} from './storage-results.js';

it('unwraps success and preserves Firebase errors at the result boundary', async () => {
    const success = await storageResult(async () => 42);
    expect(storageData(success)).toBe(42);
    const failure = new FirebaseEdgeError({
        code: 'storage/conflict',
        message: 'Conflict'
    });
    const result = await storageResult(async () => {
        throw failure;
    });
    expect(result).toEqual({ error: failure, data: null });
    expect(() => storageData(result)).toThrow(failure);
});
it('normalizes unexpected exceptions and identifies unsupported platform features', async () => {
    const { error, data } = await storageResult(async () => {
        throw new Error('network');
    });
    expect(data).toBeNull();
    expect(error?.code).toBe('storage/internal-error');
    expect(() => storageUnsupported('Filesystem paths')).toThrow(
        /Filesystem paths/
    );
});
