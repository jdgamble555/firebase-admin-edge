import { describe, expect, it, beforeEach, vi } from 'vitest';
import {
    createGitHubOAuthLoginUrl,
    createGoogleOAuthLoginUrl
} from './oauth.js';
import { exchangeCodeForGitHubIdToken } from './github-oauth.js';
import { exchangeCodeForGoogleIdToken, getToken } from './google-oauth.js';
import type { ServiceAccount } from './firebase-types.js';
import { FirebaseEdgeError } from './errors.js';
import { GitHubErrorInfo } from './auth-error-codes.js';

const restFetchMock = vi.hoisted(() => vi.fn());
const signJWTMock = vi.hoisted(() => vi.fn());

vi.mock('../rest-fetch.js', () => ({
    restFetch: restFetchMock
}));
vi.mock('./firebase-jwt.js', () => ({
    signJWT: signJWTMock
}));

beforeEach(() => {
    restFetchMock.mockReset();
    signJWTMock.mockReset();
});

describe('OAuth', () => {
    describe('URL Creation', () => {
        describe('createGitHubOAuthLoginUrl', () => {
            it('builds expected GitHub authorization URL', () => {
                const url = createGitHubOAuthLoginUrl(
                    'https://example.com/callback',
                    '/next/path',
                    'client-123'
                );
                const parsed = new URL(url);

                expect(parsed.origin + parsed.pathname).toBe(
                    'https://github.com/login/oauth/authorize'
                );
                expect(parsed.searchParams.get('client_id')).toBe('client-123');
                expect(parsed.searchParams.get('redirect_uri')).toBe(
                    'https://example.com/callback'
                );
                expect(parsed.searchParams.get('scope')).toBe(
                    'read:user user:email'
                );
                expect(
                    JSON.parse(parsed.searchParams.get('state') ?? '')
                ).toEqual({
                    next: '/next/path',
                    provider: 'github'
                });
            });

            it('handles special characters in paths', () => {
                const url = createGitHubOAuthLoginUrl(
                    'https://example.com/auth/callback',
                    '/dashboard?tab=settings&theme=dark',
                    'my-client-id'
                );
                const parsed = new URL(url);

                expect(parsed.searchParams.get('client_id')).toBe(
                    'my-client-id'
                );
                expect(parsed.searchParams.get('redirect_uri')).toBe(
                    'https://example.com/auth/callback'
                );

                const state = JSON.parse(
                    parsed.searchParams.get('state') ?? '{}'
                );
                expect(state.next).toBe('/dashboard?tab=settings&theme=dark');
                expect(state.provider).toBe('github');
            });
        });

        describe('createGoogleOAuthLoginUrl', () => {
            it('builds expected Google consent screen URL', () => {
                const url = createGoogleOAuthLoginUrl(
                    'https://example.com/callback',
                    '/next/path',
                    'client-123'
                );
                const parsed = new URL(url);

                expect(parsed.origin + parsed.pathname).toBe(
                    'https://accounts.google.com/o/oauth2/v2/auth'
                );
                expect(parsed.searchParams.get('client_id')).toBe('client-123');
                expect(parsed.searchParams.get('redirect_uri')).toBe(
                    'https://example.com/callback'
                );
                expect(parsed.searchParams.get('response_type')).toBe('code');
                expect(parsed.searchParams.get('scope')).toBe(
                    'openid email profile'
                );
                expect(parsed.searchParams.get('access_type')).toBe('offline');
                expect(parsed.searchParams.get('prompt')).toBe('consent');
                expect(
                    JSON.parse(parsed.searchParams.get('state') ?? '')
                ).toEqual({
                    next: '/next/path',
                    provider: 'google'
                });
            });
        });

        describe('URL encoding and safety', () => {
            it('properly encodes special characters in GitHub URLs', () => {
                const url = createGitHubOAuthLoginUrl(
                    'https://example.com/callback',
                    '/path with spaces & symbols!',
                    'client-123'
                );

                expect(() => new URL(url)).not.toThrow();
                const parsed = new URL(url);
                const state = JSON.parse(
                    parsed.searchParams.get('state') ?? '{}'
                );
                expect(state.next).toBe('/path with spaces & symbols!');
            });

            it('properly encodes special characters in Google URLs', () => {
                const url = createGoogleOAuthLoginUrl(
                    'https://example.com/auth/callback?foo=bar&baz=qux',
                    '/admin/users?filter=active&sort=name',
                    'client@example.com'
                );

                expect(() => new URL(url)).not.toThrow();
                const parsed = new URL(url);
                expect(parsed.searchParams.get('client_id')).toBe(
                    'client@example.com'
                );
            });
        });
    });

    describe('GitHub OAuth', () => {
        const payload = {
            code: 'auth-code',
            redirect_uri: 'https://example.com/callback',
            client_id: 'client-123',
            client_secret: 'secret-xyz'
        };

        describe('exchangeCodeForGitHubIdToken', () => {
            it('returns token data when REST call succeeds', async () => {
                const expectedData = {
                    access_token: 'gho_token',
                    token_type: 'bearer',
                    scope: 'read:user,user:email'
                };
                restFetchMock.mockResolvedValue({
                    data: expectedData,
                    error: null
                });

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

            it('handles bad verification code error', async () => {
                const githubError = {
                    error: 'bad_verification_code',
                    error_description:
                        'The code passed is incorrect or expired.'
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
                    'auth/github-bad-verification-code'
                );
            });
        });
    });

    describe('Google OAuth', () => {
        const payload = {
            code: 'auth-code',
            redirect_uri: 'https://example.com/callback',
            client_id: 'client-123',
            client_secret: 'secret-xyz'
        };

        describe('exchangeCodeForGoogleIdToken', () => {
            it('returns token data when REST call succeeds', async () => {
                const expectedData = { id_token: 'id', access_token: 'access' };
                restFetchMock.mockResolvedValue({
                    data: expectedData,
                    error: null
                });

                const result = await exchangeCodeForGoogleIdToken(
                    payload.code,
                    payload.redirect_uri,
                    payload.client_id,
                    payload.client_secret
                );

                expect(restFetchMock).toHaveBeenCalledWith(
                    'https://oauth2.googleapis.com/token',
                    expect.objectContaining({
                        body: expect.objectContaining(payload),
                        form: true
                    })
                );
                expect(result).toEqual({ data: expectedData, error: null });
            });

            it('returns upstream error when REST call fails', async () => {
                const apiError = { code: 400, message: 'invalid_grant' };
                restFetchMock.mockResolvedValue({
                    data: null,
                    error: { error: apiError }
                });

                const result = await exchangeCodeForGoogleIdToken(
                    payload.code,
                    payload.redirect_uri,
                    payload.client_id,
                    payload.client_secret
                );

                expect(result.data).toBeNull();
                expect(result.error).toBeInstanceOf(FirebaseEdgeError);
                expect(result.error?.code).toBe('auth/google-invalid-grant');
            });

            it('handles invalid client error', async () => {
                const apiError = { code: 401, message: 'invalid_client' };
                restFetchMock.mockResolvedValue({
                    data: null,
                    error: { error: apiError }
                });

                const result = await exchangeCodeForGoogleIdToken(
                    payload.code,
                    payload.redirect_uri,
                    payload.client_id,
                    payload.client_secret
                );

                expect(result.data).toBeNull();
                expect(result.error).toBeInstanceOf(FirebaseEdgeError);
                expect(result.error?.code).toBe('auth/google-invalid-client');
            });
        });

        describe('getToken', () => {
            const serviceAccount = {
                client_email: 'test@project.iam.gserviceaccount.com',
                private_key:
                    '-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n',
                token_uri: 'https://oauth2.googleapis.com/token'
            } as ServiceAccount;

            it('requests new token with signed JWT', async () => {
                const fakeFetch = vi.fn();
                const tokenData = { access_token: 'ya29', expires_in: 3600 };
                signJWTMock.mockResolvedValue({
                    data: 'signed-jwt',
                    error: null
                });
                restFetchMock.mockResolvedValue({
                    data: tokenData,
                    error: null
                });

                const result = await getToken(serviceAccount, fakeFetch);

                expect(signJWTMock).toHaveBeenCalledWith(serviceAccount);
                expect(result).toEqual({ data: tokenData, error: null });
            });

            it('short-circuits when signJWT returns error', async () => {
                const jwtError = { code: 401, message: 'bad cert', errors: [] };
                signJWTMock.mockResolvedValue({ data: null, error: jwtError });

                const result = await getToken(serviceAccount);

                expect(restFetchMock).not.toHaveBeenCalled();
                expect(result.data).toBeNull();
                expect(result.error).toBeInstanceOf(FirebaseEdgeError);
                expect(result.error?.code).toBe('auth/jwt-sign-failed');
            });

            it('reports missing JWT data', async () => {
                signJWTMock.mockResolvedValue({ data: null, error: null });

                const result = await getToken(serviceAccount);

                expect(result.data).toBeNull();
                expect(result.error).toBeInstanceOf(FirebaseEdgeError);
                expect(result.error?.code).toBe('auth/jwt-data-missing');
            });

            it('returns REST error payload from Google', async () => {
                const apiError = { code: 503, message: 'unavailable' };
                signJWTMock.mockResolvedValue({
                    data: 'signed-jwt',
                    error: null
                });
                restFetchMock.mockResolvedValue({
                    data: null,
                    error: { error: apiError }
                });

                const result = await getToken(serviceAccount);

                expect(result.data).toBeNull();
                expect(result.error).toBeInstanceOf(FirebaseEdgeError);
                expect(result.error?.code).toBe(
                    'auth/google-temporarily-unavailable'
                );
            });
        });
    });
});
