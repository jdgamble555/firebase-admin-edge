import { describe, expect, it, beforeEach, vi } from 'vitest';
import { exchangeCodeForGitHubIdToken } from './github-oauth.js';
import { FirebaseEdgeError } from './errors.js';
import { GitHubErrorInfo } from './auth-error-codes.js';

const restFetchMock = vi.hoisted(() => vi.fn());

vi.mock('../rest-fetch.js', () => ({
    restFetch: restFetchMock
}));

beforeEach(() => {
    restFetchMock.mockReset();
});

describe('GitHub OAuth Token Exchange', () => {
    const payload = {
        code: 'auth-code',
        redirect_uri: 'https://example.com/callback',
        client_id: 'client-123',
        client_secret: 'secret-xyz'
    };

    it('returns token data when REST call succeeds', async () => {
        const expectedData = {
            access_token: 'gho_token',
            token_type: 'bearer',
            scope: 'read:user,user:email'
        };
        restFetchMock.mockResolvedValue({ data: expectedData, error: null });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(restFetchMock).toHaveBeenCalledWith(
            'https://github.com/login/oauth/access_token',
            expect.objectContaining({
                body: expect.objectContaining(payload),
                form: true,
                acceptJson: true
            })
        );
        expect(result).toEqual({ data: expectedData, error: null });
    });

    it('handles incorrect client credentials error', async () => {
        const githubError = {
            error: 'incorrect_client_credentials',
            error_description:
                'The client_id and/or client_secret passed are incorrect.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe(
            'auth/github-incorrect-client-credentials'
        );
        expect(result.error?.message).toBe(
            GitHubErrorInfo.GITHUB_INCORRECT_CLIENT_CREDENTIALS.message
        );
    });

    it('handles redirect URI mismatch error', async () => {
        const githubError = {
            error: 'redirect_uri_mismatch',
            error_description:
                'The redirect_uri MUST match the registered callback URL for this application.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/github-redirect-uri-mismatch');
        expect(result.error?.message).toBe(
            GitHubErrorInfo.GITHUB_REDIRECT_URI_MISMATCH.message
        );
    });

    it('handles bad verification code error', async () => {
        const githubError = {
            error: 'bad_verification_code',
            error_description: 'The code passed is incorrect or expired.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/github-bad-verification-code');
        expect(result.error?.message).toBe(
            GitHubErrorInfo.GITHUB_BAD_VERIFICATION_CODE.message
        );
    });

    it('handles unverified user email error', async () => {
        const githubError = {
            error: 'unverified_user_email',
            error_description: 'The user must have a verified email address.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/github-unverified-user-email');
        expect(result.error?.message).toBe(
            GitHubErrorInfo.GITHUB_UNVERIFIED_USER_EMAIL.message
        );
    });

    it('handles access denied error', async () => {
        const githubError = {
            error: 'access_denied',
            error_description: 'The user denied the request.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/github-access-denied');
        expect(result.error?.message).toBe(
            GitHubErrorInfo.GITHUB_ACCESS_DENIED.message
        );
    });

    it('handles invalid client error', async () => {
        const githubError = {
            error: 'invalid_client',
            error_description: 'Client authentication failed.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/github-invalid-client');
        expect(result.error?.message).toBe(
            GitHubErrorInfo.GITHUB_INVALID_CLIENT.message
        );
    });

    it('handles invalid request error', async () => {
        const githubError = {
            error: 'invalid_request',
            error_description: 'A required parameter was missing or invalid.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/github-invalid-request');
        expect(result.error?.message).toBe(
            GitHubErrorInfo.GITHUB_INVALID_REQUEST.message
        );
    });

    it('handles unauthorized client error', async () => {
        const githubError = {
            error: 'unauthorized_client',
            error_description:
                'The client is not authorized to request an access token.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/github-unauthorized-client');
        expect(result.error?.message).toBe(
            GitHubErrorInfo.GITHUB_UNAUTHORIZED_CLIENT.message
        );
    });

    it('handles invalid scope error', async () => {
        const githubError = {
            error: 'invalid_scope',
            error_description: 'The requested scope is invalid.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/github-invalid-scope');
        expect(result.error?.message).toBe(
            GitHubErrorInfo.GITHUB_INVALID_SCOPE.message
        );
    });

    it('handles unrecognized GitHub error', async () => {
        const githubError = {
            error: 'unknown_error',
            error_description: 'Some unknown error occurred.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.data).toBeNull();
        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        expect(result.error?.code).toBe('auth/github-code-exchange-failed');
        expect(result.error?.message).toBe(
            GitHubErrorInfo.GITHUB_CODE_EXCHANGE_FAILED.message
        );
    });

    it('includes error context in FirebaseEdgeError', async () => {
        const githubError = {
            error: 'bad_verification_code',
            error_description: 'The code passed is incorrect or expired.'
        };
        restFetchMock.mockResolvedValue({
            data: null,
            error: githubError
        });

        const result = await exchangeCodeForGitHubIdToken(
            payload.code,
            payload.redirect_uri,
            payload.client_id,
            payload.client_secret
        );

        expect(result.error).toBeInstanceOf(FirebaseEdgeError);
        const firebaseError = result.error as FirebaseEdgeError;
        expect(firebaseError.context).toEqual({
            originalError: 'bad_verification_code',
            description: 'The code passed is incorrect or expired.'
        });
    });
});
