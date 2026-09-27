import { FirebaseEdgeError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';

it('exposes a structured invalid-argument error with the path validation message', () => {
    expect(() => validatePath('', true)).toThrow(
        new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Firestore path must be a non-empty string.'
        })
    );
    try {
        validatePath('', true);
    } catch (error) {
        expect(error).toMatchObject({
            code: 'firestore/invalid-argument',
            name: 'FirebaseEdgeError'
        });
    }
});
import { expect, it, vi } from 'vitest';
import { validatePath, autoId } from './firestore-path.js';

it('creates 20-character auto IDs using unbiased random bytes', () => {
    const ids = new Set(Array.from({ length: 100 }, () => autoId()));
    expect(ids.size).toBe(100);
    for (const id of ids) expect(id).toMatch(/^[A-Za-z0-9]{20}$/);
    const random = vi
        .spyOn(crypto, 'getRandomValues')
        .mockImplementationOnce((array) => {
            (array as Uint8Array).fill(255);
            return array;
        });
    expect(autoId()).toHaveLength(20);
    expect(random.mock.calls.length).toBeGreaterThan(1);
    random.mockRestore();
});

it('validates document and collection path parity', () => {
    expect(() => validatePath('users/a', true)).not.toThrow();
    expect(() => validatePath('users/a/posts', false)).not.toThrow();
    expect(() => validatePath('users', true)).toThrow('document');
    expect(() => validatePath('users/a', false)).toThrow('collection');
});

it.each(['', '/users', 'users/', 'users//a', 'users/.', 'users/..', null])(
    'rejects invalid path %s',
    (path) => {
        expect(() => validatePath(path as string, true)).toThrow(
            FirebaseEdgeError
        );
    }
);
