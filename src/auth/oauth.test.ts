import { describe, expect, it } from 'vitest';
import {
    createGitHubOAuthLoginUrl,
    createGoogleOAuthLoginUrl
} from './oauth.js';

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
                    intent: 'signin',
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
                expect(state.intent).toBe('signin');
            });

            it('adds custom parameters to URL', () => {
                const url = createGitHubOAuthLoginUrl(
                    'https://example.com/callback',
                    '/next/path',
                    'client-123',
                    'signin',
                    { login: 'testuser', allow_signup: 'false' }
                );
                const parsed = new URL(url);

                expect(parsed.searchParams.get('login')).toBe('testuser');
                expect(parsed.searchParams.get('allow_signup')).toBe('false');
            });

            it('adds additional scopes to default scopes', () => {
                const url = createGitHubOAuthLoginUrl(
                    'https://example.com/callback',
                    '/next/path',
                    'client-123',
                    'signin',
                    undefined,
                    ['repo', 'gist']
                );
                const parsed = new URL(url);

                expect(parsed.searchParams.get('scope')).toBe(
                    'read:user user:email repo gist'
                );
            });

            it('combines custom parameters and additional scopes', () => {
                const url = createGitHubOAuthLoginUrl(
                    'https://example.com/callback',
                    '/next/path',
                    'client-123',
                    'signin',
                    { login: 'testuser' },
                    ['repo']
                );
                const parsed = new URL(url);

                expect(parsed.searchParams.get('login')).toBe('testuser');
                expect(parsed.searchParams.get('scope')).toBe(
                    'read:user user:email repo'
                );
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
                    intent: 'signin',
                    next: '/next/path',
                    provider: 'google'
                });
            });

            it('adds language code parameter', () => {
                const url = createGoogleOAuthLoginUrl(
                    'https://example.com/callback',
                    '/next/path',
                    'client-123',
                    'signin',
                    'es'
                );
                const parsed = new URL(url);

                expect(parsed.searchParams.get('hl')).toBe('es');
            });

            it('adds custom parameters to URL', () => {
                const url = createGoogleOAuthLoginUrl(
                    'https://example.com/callback',
                    '/next/path',
                    'client-123',
                    'signin',
                    undefined,
                    { login_hint: 'user@example.com', hd: 'example.com' }
                );
                const parsed = new URL(url);

                expect(parsed.searchParams.get('login_hint')).toBe(
                    'user@example.com'
                );
                expect(parsed.searchParams.get('hd')).toBe('example.com');
            });

            it('adds additional scopes to default scopes', () => {
                const url = createGoogleOAuthLoginUrl(
                    'https://example.com/callback',
                    '/next/path',
                    'client-123',
                    'signin',
                    undefined,
                    undefined,
                    [
                        'https://www.googleapis.com/auth/calendar.readonly',
                        'https://www.googleapis.com/auth/drive.file'
                    ]
                );
                const parsed = new URL(url);

                expect(parsed.searchParams.get('scope')).toBe(
                    'openid email profile https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/drive.file'
                );
            });

            it('combines language code, custom parameters, and additional scopes', () => {
                const url = createGoogleOAuthLoginUrl(
                    'https://example.com/callback',
                    '/next/path',
                    'client-123',
                    'signin',
                    'fr',
                    { login_hint: 'user@example.com' },
                    ['https://www.googleapis.com/auth/calendar.readonly']
                );
                const parsed = new URL(url);

                expect(parsed.searchParams.get('hl')).toBe('fr');
                expect(parsed.searchParams.get('login_hint')).toBe(
                    'user@example.com'
                );
                expect(parsed.searchParams.get('scope')).toBe(
                    'openid email profile https://www.googleapis.com/auth/calendar.readonly'
                );
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
                expect(state.intent).toBe('signin');
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
});
