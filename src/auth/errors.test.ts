import { describe, it, expect } from 'vitest';
import {
    ensureError,
    FirebaseEdgeError,
    FirebaseAdminAuthErrorInfo
} from './errors.js';

describe('Error Utilities', () => {
    describe('ensureError', () => {
        it('returns the error if already an Error instance', () => {
            const error = new Error('Test error');
            const result = ensureError(error);

            expect(result).toBe(error);
            expect(result.message).toBe('Test error');
        });

        it('returns the FirebaseEdgeError if already a FirebaseEdgeError', () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND
            );
            const result = ensureError(error);

            expect(result).toBe(error);
            expect(result).toBeInstanceOf(FirebaseEdgeError);
        });

        it('wraps non-Error values in an Error with stringified content', () => {
            const value = { code: 400, message: 'Bad Request' };
            const result = ensureError(value);

            expect(result).toBeInstanceOf(Error);
            expect(result.message).toContain('This value was thrown as is');
            expect(result.message).toContain('400');
            expect(result.message).toContain('Bad Request');
        });

        it('handles string values', () => {
            const value = 'Something went wrong';
            const result = ensureError(value);

            expect(result).toBeInstanceOf(Error);
            expect(result.message).toContain('This value was thrown as is');
            expect(result.message).toContain('Something went wrong');
        });

        it('handles number values', () => {
            const value = 404;
            const result = ensureError(value);

            expect(result).toBeInstanceOf(Error);
            expect(result.message).toContain('This value was thrown as is');
            expect(result.message).toContain('404');
        });

        it('handles null values', () => {
            const result = ensureError(null);

            expect(result).toBeInstanceOf(Error);
            expect(result.message).toContain('This value was thrown as is');
            expect(result.message).toContain('null');
        });

        it('handles undefined values', () => {
            const result = ensureError(undefined);

            expect(result).toBeInstanceOf(Error);
            expect(result.message).toContain('This value was thrown as is');
        });

        it('handles circular references gracefully', () => {
            const circular: any = { name: 'circular' };
            circular.self = circular;

            const result = ensureError(circular);

            expect(result).toBeInstanceOf(Error);
            expect(result.message).toContain(
                'Unable to stringify the thrown value'
            );
        });
    });

    describe('FirebaseEdgeError', () => {
        it('creates error with message and code', () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND
            );

            expect(error).toBeInstanceOf(Error);
            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.name).toBe('FirebaseEdgeError');
            expect(error.message).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND.message
            );
            expect(error.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND.code
            );
        });

        it('includes cause when provided', () => {
            const cause = new Error('Original error');
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_VERIFY_FAILED,
                { cause }
            );

            expect(error.cause).toBe(cause);
            expect(error.message).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_VERIFY_FAILED.message
            );
        });

        it('includes context when provided', () => {
            const context = { uid: 'user-123', provider: 'google.com' };
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED,
                { context }
            );

            expect(error.context).toEqual(context);
            expect(error.message).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED.message
            );
        });

        it('includes both cause and context', () => {
            const cause = new Error('Network failure');
            const context = { url: 'https://api.example.com', timeout: 5000 };
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_API_NETWORK_ERROR,
                { cause, context }
            );

            expect(error.cause).toBe(cause);
            expect(error.context).toEqual(context);
            expect(error.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_API_NETWORK_ERROR.code
            );
        });

        it('works without options', () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_UNKNOWN_ERROR
            );

            expect(error.cause).toBeUndefined();
            expect(error.context).toBeUndefined();
            expect(error.message).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_UNKNOWN_ERROR.message
            );
        });

        it('maintains prototype chain', () => {
            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_INTERNAL_ERROR
            );

            expect(error instanceof FirebaseEdgeError).toBe(true);
            expect(error instanceof Error).toBe(true);
            expect(Object.getPrototypeOf(error)).toBe(
                FirebaseEdgeError.prototype
            );
        });

        it('is catchable and type-checkable', () => {
            try {
                throw new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_TOKEN_REVOCATION_CHECK_FAILED,
                    { context: { reason: 'test' } }
                );
            } catch (err) {
                expect(err).toBeInstanceOf(FirebaseEdgeError);
                if (err instanceof FirebaseEdgeError) {
                    expect(err.code).toBe(
                        FirebaseAdminAuthErrorInfo
                            .ADMIN_TOKEN_REVOCATION_CHECK_FAILED.code
                    );
                    expect(err.context).toEqual({ reason: 'test' });
                }
            }
        });

        it('supports nested JSON context', () => {
            const context = {
                user: { id: '123', email: 'test@example.com' },
                metadata: { timestamp: 1234567890, source: 'api' },
                tags: ['urgent', 'security']
            };

            const error = new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_OPERATION_FAILED,
                { context }
            );

            expect(error.context).toEqual(context);
        });
    });
});
