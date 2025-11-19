import { describe, it, expect } from 'vitest';
import { FirebaseEdgeError } from './auth/errors.js';
import { FirebaseEdgeServerErrorInfo } from './firebase-edge-errors.js';

describe('firebase-edge-errors', () => {
    describe('FirebaseEdgeServerErrorInfo', () => {
        it('contains all required error definitions', () => {
            expect(
                FirebaseEdgeServerErrorInfo.EDGE_PROVIDER_NOT_CONFIGURED
            ).toBeDefined();
            expect(
                FirebaseEdgeServerErrorInfo.EDGE_GOOGLE_PROVIDER_NOT_CONFIGURED
            ).toBeDefined();
            expect(
                FirebaseEdgeServerErrorInfo.EDGE_GITHUB_PROVIDER_NOT_CONFIGURED
            ).toBeDefined();
            expect(
                FirebaseEdgeServerErrorInfo.EDGE_NO_PROVIDER_IN_STATE
            ).toBeDefined();
            expect(
                FirebaseEdgeServerErrorInfo.EDGE_NO_OAUTH_TOKEN
            ).toBeDefined();
            expect(FirebaseEdgeServerErrorInfo.EDGE_NO_ID_TOKEN).toBeDefined();
            expect(
                FirebaseEdgeServerErrorInfo.EDGE_NO_SESSION_COOKIE
            ).toBeDefined();
            expect(
                FirebaseEdgeServerErrorInfo.EDGE_NO_CUSTOM_TOKEN_SIGNED
            ).toBeDefined();
            expect(
                FirebaseEdgeServerErrorInfo.EDGE_SESSION_EXPIRED
            ).toBeDefined();
            expect(
                FirebaseEdgeServerErrorInfo.EDGE_ACCOUNT_EXISTS_DIFFERENT_METHOD
            ).toBeDefined();
        });

        it('has proper error structure for provider configuration errors', () => {
            const error =
                FirebaseEdgeServerErrorInfo.EDGE_GOOGLE_PROVIDER_NOT_CONFIGURED;

            expect(error).toHaveProperty('code');
            expect(error).toHaveProperty('message');
            expect(error.code).toBe('edge/google-provider-not-configured');
            expect(error.message).toContain('Google');
        });

        it('has proper error structure for OAuth flow errors', () => {
            const error = FirebaseEdgeServerErrorInfo.EDGE_NO_OAUTH_TOKEN;

            expect(error).toHaveProperty('code');
            expect(error).toHaveProperty('message');
            expect(error.code).toBe('edge/no-oauth-token');
            expect(error.message).toContain('OAuth token');
        });

        it('has proper error structure for session management errors', () => {
            const error = FirebaseEdgeServerErrorInfo.EDGE_SESSION_EXPIRED;

            expect(error).toHaveProperty('code');
            expect(error).toHaveProperty('message');
            expect(error.code).toBe('edge/session-expired');
            expect(error.message).toContain('session');
        });
    });

    describe('FirebaseEdgeError with edge-specific errors', () => {
        it('creates proper error instance with provider configuration error', () => {
            const error = new FirebaseEdgeError(
                FirebaseEdgeServerErrorInfo.EDGE_GOOGLE_PROVIDER_NOT_CONFIGURED
            );

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error).toBeInstanceOf(Error);
            expect(error.code).toBe('edge/google-provider-not-configured');
            expect(error.message).toContain('Google provider not configured');
        });

        it('creates proper error instance with OAuth flow error', () => {
            const error = new FirebaseEdgeError(
                FirebaseEdgeServerErrorInfo.EDGE_NO_OAUTH_TOKEN
            );

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error).toBeInstanceOf(Error);
            expect(error.code).toBe('edge/no-oauth-token');
            expect(error.message).toContain('OAuth token obtained');
        });

        it('creates proper error instance with session management error', () => {
            const error = new FirebaseEdgeError(
                FirebaseEdgeServerErrorInfo.EDGE_SESSION_EXPIRED
            );

            expect(error).toBeInstanceOf(FirebaseEdgeError);
            expect(error).toBeInstanceOf(Error);
            expect(error.code).toBe('edge/session-expired');
            expect(error.message).toContain('session has expired');
        });

        it('includes additional context when provided', () => {
            const context = {
                provider: 'google',
                redirectUri: 'http://localhost'
            };
            const error = new FirebaseEdgeError(
                FirebaseEdgeServerErrorInfo.EDGE_GOOGLE_PROVIDER_NOT_CONFIGURED,
                { context }
            );

            expect(error.context).toEqual(context);
        });
    });
});
