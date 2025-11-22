import type { CookieConfig, CookieOptions } from './auth/cookie-types.js';
import { FirebaseAdminAuth } from './auth/firebase-admin-auth.js';
import { FirebaseAuth } from './auth/firebase-auth.js';
import { signJWTCustomToken } from './auth/firebase-jwt.js';
import type { FirebaseConfig, ServiceAccount } from './auth/firebase-types.js';
import { exchangeCodeForGitHubIdToken } from './auth/github-oauth.js';
import { exchangeCodeForGoogleIdToken } from './auth/google-oauth.js';
import {
    createGitHubOAuthLoginUrl,
    createGoogleOAuthLoginUrl
} from './auth/oauth.js';
import { FirebaseEdgeError } from './auth/errors.js';
import { FirebaseEdgeServerErrorInfo } from './firebase-edge-errors.js';
import type { CacheConfig } from './auth/cache-types.js';

const COOKIE_LIFETIME_SECONDS = 60 * 60 * 24 * 5; // 5 days

const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: COOKIE_LIFETIME_SECONDS
} as CookieOptions;

/**
 * Official Firebase OAuth providers
 */
export const OFFICIAL_FIREBASE_OAUTH_PROVIDERS = [
    'google',
    'facebook',
    'apple',
    'twitter',
    'github',
    'microsoft',
    'yahoo',
    'playgames'
] as const;

type ProviderList = (typeof OFFICIAL_FIREBASE_OAUTH_PROVIDERS)[number];

type ProviderConfig = Partial<
    Record<
        ProviderList,
        {
            client_id: string;
            client_secret: string;
        }
    >
>;

/**
 * Creates a Firebase Edge Server for authentication and session management in edge environments.
 *
 * @param config Configuration object
 * @param config.serviceAccount Firebase service account for admin operations
 * @param config.firebaseConfig Firebase client configuration
 * @param config.providers OAuth provider configurations (Google, GitHub, etc.)
 * @param config.cookies Cookie management functions (getSession, saveSession)
 * @param config.redirectUri OAuth callback redirect URI
 * @param config.cache Optional cache implementation for token caching
 * @param config.cacheName Optional cache key name for token storage
 * @param config.cookieName Optional custom session cookie name (defaults to '__session')
 * @param config.cookieOptions Optional cookie configuration overrides
 * @param config.tenantId Optional Firebase Auth tenant ID for multi-tenancy
 * @param config.autoLinkProviders Optional flag to automatically link accounts with same email
 * @param config.fetch Optional custom fetch implementation
 * @returns Object with authentication methods (auth, adminAuth, signOut, getUser, getGoogleLoginURL, getGitHubLoginURL, signInWithCallback, getToken)
 */
export function createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig,
    providers,
    cookies,
    cookieName,
    cookieOptions,
    cache,
    cacheName,
    tenantId,
    redirectUri,
    autoLinkProviders,
    fetch
}: {
    serviceAccount: ServiceAccount;
    firebaseConfig: FirebaseConfig;
    providers: ProviderConfig;
    cookies: CookieConfig;
    cache?: CacheConfig;
    cacheName?: string;
    cookieName?: string;
    cookieOptions?: Partial<CookieOptions>;
    redirectUri: string;
    tenantId?: string;
    autoLinkProviders?: boolean;
    fetch?: typeof globalThis.fetch;
}) {
    // Cookies
    const _cookieName = cookieName || '__session';

    const { getSession, saveSession } = cookies;

    const _cookieOptions = { ...COOKIE_OPTIONS, ...cookieOptions };

    // Fetch
    const fetchImpl = fetch ?? globalThis.fetch;

    const cacheImpl = cache ?? undefined;

    // Auth instances
    const auth = new FirebaseAuth(
        firebaseConfig,
        redirectUri,
        tenantId,
        fetchImpl
    );
    const adminAuth = new FirebaseAdminAuth(
        serviceAccount,
        tenantId,
        fetchImpl,
        cacheImpl,
        cacheName
    );

    /**
     * Clears the session cookie by setting its maxAge to 0.
     */
    function deleteSession() {
        saveSession(_cookieName, '', {
            ..._cookieOptions,
            maxAge: 0
        });
    }

    /**
     * Signs out the current user by clearing the session cookie.
     * Note: This only removes the server-side session, not Firebase client tokens.
     *
     * @returns void
     */
    function signOut() {
        deleteSession();
        return;
    }

    /**
     * Gets the current authenticated user from the session cookie.
     *
     * @param checkRevoked Whether to check if the token has been revoked (defaults to false)
     * @returns Promise resolving to object with decoded token data or null, and error if any
     */
    async function getUser(checkRevoked: boolean = false) {
        const sessionCookie = await getSession(_cookieName);

        if (!sessionCookie) {
            return {
                data: null,
                error: null
            };
        }

        const { data: decodedToken, error: verifyError } =
            await adminAuth.verifySessionCookie(sessionCookie, checkRevoked);

        if (verifyError) {
            deleteSession();

            return {
                data: null,
                error: verifyError
            };
        }

        if (!decodedToken) {
            deleteSession();

            return {
                data: null,
                error: null
            };
        }

        return {
            data: decodedToken,
            error: null
        };
    }

    /**
     * Generates a Google OAuth login URL and clears any existing session.
     *
     * @param next State parameter for the OAuth flow (typically the redirect path after login)
     * @param options Optional configuration object
     * @param options.languageCode ISO 639-1 language code (e.g., 'en', 'es', 'fr')
     * @param options.customParameters Custom OAuth parameters (e.g., { login_hint: 'user@example.com', hd: 'example.com' })
     * @param options.addScopes Additional OAuth scopes (e.g., ['https://www.googleapis.com/auth/calendar.readonly'])
     * @returns Promise resolving to Google OAuth login URL string
     * @throws {FirebaseEdgeError} If Google provider is not configured
     */
    async function getGoogleLoginURL(
        next: string,
        options?: {
            languageCode?: string;
            customParameters?: Record<string, string>;
            addScopes?: string[];
        }
    ) {
        deleteSession();

        if (!providers.google) {
            throw new FirebaseEdgeError(
                FirebaseEdgeServerErrorInfo.EDGE_GOOGLE_PROVIDER_NOT_CONFIGURED
            );
        }

        const { client_id } = providers.google;

        return createGoogleOAuthLoginUrl(
            redirectUri,
            next,
            client_id,
            options?.languageCode,
            options?.customParameters,
            options?.addScopes
        );
    }

    /**
     * Generates a GitHub OAuth login URL and clears any existing session.
     * Note: GitHub doesn't support language parameters - language is determined by user's browser/account settings.
     *
     * @param next State parameter for the OAuth flow (typically the redirect path after login)
     * @param options Optional configuration object
     * @param options.customParameters Custom OAuth parameters (e.g., { login: 'username', allow_signup: 'false' })
     * @param options.addScopes Additional OAuth scopes (e.g., ['repo', 'gist'])
     * @returns Promise resolving to GitHub OAuth login URL string
     * @throws {FirebaseEdgeError} If GitHub provider is not configured
     */
    async function getGitHubLoginURL(
        next: string,
        options?: {
            customParameters?: Record<string, string>;
            addScopes?: string[];
        }
    ) {
        deleteSession();

        if (!providers.github) {
            throw new FirebaseEdgeError(
                FirebaseEdgeServerErrorInfo.EDGE_GITHUB_PROVIDER_NOT_CONFIGURED
            );
        }

        const { client_id } = providers.github;

        return createGitHubOAuthLoginUrl(
            redirectUri,
            next,
            client_id,
            options?.customParameters,
            options?.addScopes
        );
    }

    async function signInWithProviderToken(
        provider: string,
        oauthToken: string
    ) {
        const providerId = provider === 'google' ? 'google.com' : 'github.com';

        const { data: signInData, error: signInError } =
            await auth.signInWithProvider(oauthToken, providerId);

        if (signInError) {
            return {
                error: signInError
            };
        }

        if (!signInData) {
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_SIGN_IN_DATA
                )
            };
        }

        // Account exists with that email but different sign-in method
        if (signInData.needConfirmation) {
            if (!autoLinkProviders) {
                return {
                    error: new FirebaseEdgeError(
                        FirebaseEdgeServerErrorInfo.EDGE_ACCOUNT_EXISTS_DIFFERENT_METHOD
                    )
                };
            }

            if (!signInData.email) {
                return {
                    error: new FirebaseEdgeError(
                        FirebaseEdgeServerErrorInfo.EDGE_NO_EMAIL_FOR_AUTO_LINKING
                    )
                };
            }

            const { data, error: getEmailError } =
                await adminAuth.getUserByEmail(signInData.email);

            if (getEmailError) {
                return {
                    error: getEmailError
                };
            }

            if (!data?.localId) {
                return {
                    error: new FirebaseEdgeError(
                        FirebaseEdgeServerErrorInfo.EDGE_NO_USER_RECORD
                    )
                };
            }

            const { data: customTokenData, error: tokenError } =
                await adminAuth.createCustomToken(data.localId);

            if (tokenError) {
                return {
                    data: null,
                    error: tokenError
                };
            }

            const { data: customSignInData, error: customSignInError } =
                await auth.signInWithCustomToken(customTokenData);

            if (customSignInError) {
                return {
                    data: null,
                    error: customSignInError
                };
            }

            if (!customSignInData?.idToken) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseEdgeServerErrorInfo.EDGE_NO_ID_TOKEN
                    )
                };
            }

            const { data: linkData, error: linkError } =
                await auth.linkWithCredential(
                    customSignInData.idToken,
                    oauthToken,
                    providerId
                );

            if (linkError) {
                return {
                    data: null,
                    error: linkError
                };
            }

            return {
                data: linkData,
                error: null
            };
        }

        return {
            data: signInData,
            error: signInError
        };
    }

    /**
     * Completes OAuth flow by exchanging authorization code for a session.
     *
     * @param url URL containing authorization code and state from OAuth callback
     * @param expiresIn_ms Session cookie expiration time in milliseconds (defaults to 5 days)
     * @returns Promise resolving to object with next redirect path and error if any
     */
    async function signInWithCallback(
        url: URL,
        expiresIn_ms: number = COOKIE_LIFETIME_SECONDS * 1000
    ) {
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');

        if (!code) {
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_AUTHORIZATION_CODE
                )
            };
        }

        let next = '/';
        let provider = null;

        try {
            const parsed = state && JSON.parse(state);
            next = parsed?.next ?? '/';
            provider = parsed?.provider ?? null;
        } catch {}

        if (!provider) {
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_PROVIDER_IN_STATE
                )
            };
        }

        let oauthToken: string | null = null;

        if (providers.google && provider === 'google') {
            const { client_id, client_secret } = providers.google;

            const { data: googleData, error: exchangeError } =
                await exchangeCodeForGoogleIdToken(
                    code,
                    redirectUri,
                    client_id,
                    client_secret,
                    fetchImpl
                );

            if (exchangeError) {
                return {
                    error: exchangeError
                };
            }

            if (!googleData) {
                return {
                    error: new FirebaseEdgeError(
                        FirebaseEdgeServerErrorInfo.EDGE_NO_EXCHANGE_DATA
                    )
                };
            }

            oauthToken = googleData.id_token;
        } else if (providers.github && provider === 'github') {
            const { client_id, client_secret } = providers.github;

            const { data: githubData, error: exchangeError } =
                await exchangeCodeForGitHubIdToken(
                    code,
                    redirectUri,
                    client_id,
                    client_secret,
                    fetchImpl
                );

            if (exchangeError) {
                return {
                    error: exchangeError
                };
            }

            if (!githubData) {
                return {
                    error: new FirebaseEdgeError(
                        FirebaseEdgeServerErrorInfo.EDGE_NO_EXCHANGE_DATA
                    )
                };
            }

            oauthToken = githubData.access_token;
        }

        if (!oauthToken) {
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_OAUTH_TOKEN
                )
            };
        }

        const { data: signInData, error: signInError } =
            await signInWithProviderToken(provider, oauthToken);

        if (signInError) {
            return {
                error: signInError
            };
        }

        if (!signInData) {
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_SIGN_IN_DATA
                )
            };
        }

        const { idToken } = signInData;

        if (!idToken) {
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_ID_TOKEN
                )
            };
        }

        const { data: sessionCookie, error: sessionError } =
            await adminAuth.createSessionCookie(idToken, expiresIn_ms);

        if (sessionError) {
            return {
                error: sessionError
            };
        }

        if (!sessionCookie) {
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_SESSION_COOKIE
                )
            };
        }

        saveSession(_cookieName, sessionCookie, _cookieOptions);

        return {
            data: next,
            error: null
        };
    }

    /**
     * Generates fresh Firebase client tokens for the authenticated user.
     * Creates a custom token and exchanges it for a Firebase ID token and refresh token.
     *
     * @returns Promise resolving to object with Firebase tokens (idToken, refreshToken, expiresIn) and error if any
     */
    async function getToken() {
        const { data: verifiedToken, error: verifyError } = await getUser();

        if (verifyError) {
            return {
                data: null,
                error: verifyError
            };
        }

        if (!verifiedToken) {
            return {
                data: null,
                error: null
            };
        }

        const claims = tenantId ? { tenant_id: tenantId } : {};

        const { data: signJWTData, error: signJWTError } =
            await signJWTCustomToken(verifiedToken.sub, serviceAccount, claims);

        if (signJWTError) {
            return {
                data: null,
                error: signJWTError
            };
        }

        if (!signJWTData) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_CUSTOM_TOKEN_SIGNED
                )
            };
        }

        const { data: signInData, error: signInError } =
            await auth.signInWithCustomToken(signJWTData);

        if (signInError) {
            return {
                data: null,
                error: signInError
            };
        }

        if (!signInData) {
            return {
                data: null,
                error: null
            };
        }

        return {
            data: signInData,
            error: null
        };
    }

    return {
        auth,
        adminAuth,
        signOut,
        getUser,
        getGoogleLoginURL,
        getGitHubLoginURL,
        signInWithCallback,
        getToken
    };
}
