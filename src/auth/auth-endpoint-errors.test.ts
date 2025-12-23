import { describe, it, expect } from 'vitest';
import { mapFirebaseError } from './auth-endpoint-errors.js';
import { FirebaseEdgeError, FirebaseEndpointErrorInfo } from './errors.js';

describe('mapFirebaseError', () => {
    describe('Token Errors', () => {
        it('maps INVALID_CUSTOM_TOKEN to structured error', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'INVALID_CUSTOM_TOKEN: Token format invalid'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_CUSTOM_TOKEN.code
            );
        });

        it('maps INVALID_REFRESH_TOKEN to structured error', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'INVALID_REFRESH_TOKEN'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_REFRESH_TOKEN.code
            );
        });

        it('maps INVALID_GRANT to refresh token error', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'INVALID_GRANT: Token has been revoked'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_REFRESH_TOKEN.code
            );
        });

        it('maps TOKEN_EXPIRED to structured error', () => {
            const error = mapFirebaseError({
                code: 401,
                message: 'TOKEN_EXPIRED'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_TOKEN_EXPIRED.code
            );
        });

        it('maps CREDENTIAL_TOO_OLD_LOGIN_AGAIN to token expired', () => {
            const error = mapFirebaseError({
                code: 401,
                message: 'CREDENTIAL_TOO_OLD_LOGIN_AGAIN'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_TOKEN_EXPIRED.code
            );
        });

        it('maps INVALID_ID_TOKEN to structured error', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'INVALID_ID_TOKEN'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ID_TOKEN.code
            );
        });

        it('maps INVALID_CREDENTIAL to structured error', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'INVALID_CREDENTIAL'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_CREDENTIAL.code
            );
        });
    });

    describe('User Management Errors', () => {
        it('maps USER_NOT_FOUND to structured error', () => {
            const error = mapFirebaseError({
                code: 404,
                message: 'USER_NOT_FOUND'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND.code
            );
        });

        it('maps EMAIL_NOT_FOUND to user not found error', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'EMAIL_NOT_FOUND'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND.code
            );
        });

        it('maps USER_DISABLED to structured error', () => {
            const error = mapFirebaseError({
                code: 403,
                message: 'USER_DISABLED'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_USER_DISABLED.code
            );
        });
    });

    describe('Permission & Access Errors', () => {
        it('maps PERMISSION_DENIED to structured error', () => {
            const error = mapFirebaseError({
                code: 403,
                message: 'PERMISSION_DENIED'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED.code
            );
        });

        it('maps INSUFFICIENT_PERMISSION to structured error', () => {
            const error = mapFirebaseError({
                code: 403,
                message: 'INSUFFICIENT_PERMISSION'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INSUFFICIENT_PERMISSION.code
            );
        });
    });

    describe('Rate Limiting & Quota Errors', () => {
        it('maps TOO_MANY_ATTEMPTS_TRY_LATER to structured error', () => {
            const error = mapFirebaseError({
                code: 429,
                message: 'TOO_MANY_ATTEMPTS_TRY_LATER'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_TOO_MANY_REQUESTS.code
            );
        });

        it('maps QUOTA_EXCEEDED to structured error', () => {
            const error = mapFirebaseError({
                code: 429,
                message: 'QUOTA_EXCEEDED'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_QUOTA_EXCEEDED.code
            );
        });
    });

    describe('Provider & Configuration Errors', () => {
        it('maps OPERATION_NOT_ALLOWED to provider not enabled', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'OPERATION_NOT_ALLOWED'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_PROVIDER_NOT_ENABLED.code
            );
        });

        it('maps INVALID_IDP_RESPONSE to invalid provider id', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'INVALID_IDP_RESPONSE'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_PROVIDER_ID.code
            );
        });
    });

    describe('API Key Errors', () => {
        it('maps API KEY NOT VALID to structured error', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'API KEY NOT VALID'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_API_KEY.code
            );
        });

        it('maps INVALID_API_KEY to structured error', () => {
            const error = mapFirebaseError({
                code: 403,
                message: 'INVALID_API_KEY'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_API_KEY.code
            );
        });
    });

    describe('Validation Errors', () => {
        it('maps INVALID_EMAIL to invalid argument', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'INVALID_EMAIL'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT.code
            );
        });

        it('maps WEAK_PASSWORD to invalid argument', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'WEAK_PASSWORD'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT.code
            );
        });

        it('maps EMAIL_EXISTS to invalid argument', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'EMAIL_EXISTS'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT.code
            );
        });

        it('maps INVALID_PASSWORD to invalid argument', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'INVALID_PASSWORD'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT.code
            );
        });

        it('maps MISSING_REFRESH_TOKEN to invalid argument', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'MISSING_REFRESH_TOKEN'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT.code
            );
        });

        it('maps MISSING_LOCAL_ID to invalid argument', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'MISSING_LOCAL_ID'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT.code
            );
        });

        it('maps INVALID_GRANT_TYPE to invalid refresh token', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'INVALID_GRANT_TYPE'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_REFRESH_TOKEN.code
            );
        });
    });

    describe('Reason Code Mapping', () => {
        it('maps INVALID reason to invalid argument', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'Some error',
                errors: [
                    {
                        reason: 'INVALID',
                        message: 'Invalid request',
                        domain: 'global'
                    }
                ]
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT.code
            );
        });

        it('maps FORBIDDEN reason to forbidden', () => {
            const error = mapFirebaseError({
                code: 403,
                message: 'Access denied',
                errors: [
                    {
                        reason: 'FORBIDDEN',
                        message: 'No access',
                        domain: 'global'
                    }
                ]
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_FORBIDDEN.code
            );
        });

        it('maps NOTFOUND reason to user not found', () => {
            const error = mapFirebaseError({
                code: 404,
                message: 'Resource not found',
                errors: [
                    {
                        reason: 'NOTFOUND',
                        message: 'Not found',
                        domain: 'global'
                    }
                ]
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND.code
            );
        });

        it('maps NOT_FOUND reason to user not found', () => {
            const error = mapFirebaseError({
                code: 404,
                message: 'Resource not found',
                errors: [
                    {
                        reason: 'NOT_FOUND',
                        message: 'Not found',
                        domain: 'global'
                    }
                ]
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND.code
            );
        });
    });

    describe('HTTP Status Code Fallbacks', () => {
        it('maps 400 to invalid argument', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'Unknown error'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT.code
            );
        });

        it('maps 401 to unauthorized', () => {
            const error = mapFirebaseError({
                code: 401,
                message: 'Unauthorized'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_UNAUTHORIZED.code
            );
        });

        it('maps 403 to forbidden', () => {
            const error = mapFirebaseError({
                code: 403,
                message: 'Forbidden'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_FORBIDDEN.code
            );
        });

        it('maps 404 to user not found', () => {
            const error = mapFirebaseError({
                code: 404,
                message: 'Not found'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND.code
            );
        });

        it('maps 429 to too many requests', () => {
            const error = mapFirebaseError({
                code: 429,
                message: 'Rate limit exceeded'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_TOO_MANY_REQUESTS.code
            );
        });

        it('maps 500 to internal error', () => {
            const error = mapFirebaseError({
                code: 500,
                message: 'Internal server error'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INTERNAL_ERROR.code
            );
        });

        it('maps 502 to bad gateway', () => {
            const error = mapFirebaseError({
                code: 502,
                message: 'Bad gateway'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_BAD_GATEWAY.code
            );
        });

        it('maps 503 to service unavailable', () => {
            const error = mapFirebaseError({
                code: 503,
                message: 'Service unavailable'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_SERVICE_UNAVAILABLE.code
            );
        });

        it('maps 504 to timeout', () => {
            const error = mapFirebaseError({
                code: 504,
                message: 'Gateway timeout'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_TIMEOUT.code
            );
        });
    });

    describe('Unknown Errors', () => {
        it('maps unknown status code to unknown error with context', () => {
            const error = mapFirebaseError({
                code: 418,
                message: "I'm a teapot",
                errors: [
                    {
                        reason: 'TEAPOT',
                        message: 'Cannot brew coffee',
                        domain: 'global'
                    }
                ]
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_UNKNOWN_ERROR.code
            );
            expect(error.cause).toBeInstanceOf(Error);
            expect(error.context).toEqual({
                firebaseCode: 418,
                firebaseMessage: "I'm a teapot",
                firebaseErrors: [
                    {
                        reason: 'TEAPOT',
                        message: 'Cannot brew coffee',
                        domain: 'global'
                    }
                ]
            });
        });

        it('handles missing message field', () => {
            const error = mapFirebaseError({
                code: 999,
                message: undefined as any
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_UNKNOWN_ERROR.code
            );
        });
    });

    describe('Case Insensitivity', () => {
        it('handles lowercase error codes', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'invalid_custom_token'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_CUSTOM_TOKEN.code
            );
        });

        it('handles mixed case error codes', () => {
            const error = mapFirebaseError({
                code: 400,
                message: 'User_Not_Found'
            });

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error.code).toBe(
                FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND.code
            );
        });
    });
});
