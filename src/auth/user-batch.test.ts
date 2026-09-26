import { describe, expect, it } from 'vitest';
import {
    createBatchUserResult,
    validateDeleteUsers,
    type BatchUserError
} from './user-batch.js';
import { FirebaseEdgeError } from './errors.js';

describe('validateDeleteUsers', () => {
    it('accepts empty and maximum-size batches including duplicates', () => {
        expect(validateDeleteUsers([])).toBeNull();
        expect(validateDeleteUsers(Array(1000).fill('uid'))).toBeNull();
    });
    it.each([
        null,
        'uid',
        {},
        Array(1001).fill('uid'),
        [''],
        ['a'.repeat(129)],
        [1]
    ])('rejects invalid batch %j', (uids) => {
        expect(validateDeleteUsers(uids as string[])).toBeInstanceOf(
            FirebaseEdgeError
        );
    });
});
describe('createBatchUserResult', () => {
    it('counts missing users as successes when no API failures are returned', () => {
        expect(createBatchUserResult([0, 1])).toEqual({
            successCount: 2,
            failureCount: 0,
            errors: []
        });
        expect(createBatchUserResult([])).toEqual({
            successCount: 0,
            failureCount: 0,
            errors: []
        });
    });
    it('maps import failures back to the original indices and sorts local and remote errors', () => {
        const error = new FirebaseEdgeError({ message: 'Invalid email' });
        const result = createBatchUserResult(
            [0, 2, 3],
            [{ index: 2, message: 'DUPLICATE_LOCAL_ID' }],
            [{ index: 1, error }],
            'import'
        );
        expect(result).toMatchObject({
            successCount: 2,
            failureCount: 2,
            errors: [
                { index: 1, error },
                {
                    index: 3,
                    error: {
                        code: 'auth/admin-invalid-user-import',
                        message: 'DUPLICATE_LOCAL_ID'
                    }
                }
            ]
        });
    });
    it('returns a structured error for a failed deletion', () => {
        expect(createBatchUserResult([0], [{ index: 0 }])).toMatchObject({
            successCount: 0,
            failureCount: 1,
            errors: [
                { index: 0, error: { code: 'auth/admin-delete-user-failed' } }
            ]
        });
    });
    it.each([
        null,
        {},
        [{ index: -1 }],
        [{ index: 2 }],
        [{ index: 0.5 }],
        [{}],
        [{ index: 0 }, { index: 0 }]
    ])('rejects corrupt error indices %j', (failures) => {
        expect(() =>
            createBatchUserResult([0, 1], failures as BatchUserError[])
        ).toThrow();
    });
});
