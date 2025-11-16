import type {
    CookieOptions,
    GetSession,
    SetSession
} from './auth/cookie-types.js';
import { FirebaseAdminAuth } from './auth/firebase-admin-auth.js';
import { FirebaseAuth } from './auth/firebase-auth.js';
import { signJWTCustomToken } from './auth/firebase-jwt.js';
import type { FirebaseConfig, ServiceAccount } from './auth/firebase-types.js';
import {
    createGitHubOAuthLoginUrl,
    exchangeCodeForGitHubIdToken
} from './auth/github-oauth.js';
import {
    createGoogleOAuthLoginUrl,
    exchangeCodeForGoogleIdToken
} from './auth/google-oauth.js';

const DEFAULT_SESSION_NAME = '__session';

const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 5 * 1000
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

type CookieConfig = {
    getSession: GetSession;
    saveSession: SetSession;
    sessionName?: string;
};

/**
 * Creates a Firebase Edge Server for authentication and session management in edge environments.
 *
 * @param config Configuration object
 * @param config.serviceAccount Firebase service account for admin operations
 * @param config.firebaseConfig Firebase client configuration
 * @param config.providers OAuth provider configurations (Google, GitHub, etc.)
 * @param config.cookies Cookie management functions
 * @param config.fetch Optional custom fetch implementation
 * @returns Object with authentication methods
 */
export function createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig,
    providers,
    cookies,
    fetch
}: {
    serviceAccount: ServiceAccount;
    firebaseConfig: FirebaseConfig;
    providers: ProviderConfig;
    cookies: CookieConfig;
    fetch?: typeof globalThis.fetch;
}) {
    const sessionName = cookies.sessionName || DEFAULT_SESSION_NAME;
    const getSession = cookies.getSession;
    const saveSession = cookies.saveSession;

    const fetchImpl = fetch ?? globalThis.fetch;

    const auth = new FirebaseAuth(firebaseConfig, fetchImpl);
    const adminAuth = new FirebaseAdminAuth(serviceAccount, fetchImpl);

    /**
     * Clears the session cookie
     * @internal
     */
    function deleteSession() {
        saveSession(sessionName, '', {
            ...COOKIE_OPTIONS,
            maxAge: 0
        });
    }

    /**
     * Signs out the current user by clearing the session cookie.
     * Note: This only removes the server-side session, not Firebase client tokens.
     */
    function signOut() {
        deleteSession();
        return;
    }

    /**
     * Gets the current authenticated user from the session cookie.
     *
     * @param checkRevoked Whether to check if the token has been revoked
     * @returns Promise with user data and error
     */
    async function getUser(checkRevoked: boolean = false) {
        const sessionCookie = await getSession(sessionName);

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
     * @param redirect_uri OAuth redirect URI
     * @param path State parameter for the OAuth flow
     * @returns Google OAuth login URL
     * @throws Error if Google provider not configured
     */
    async function getGoogleLoginURL(redirect_uri: string, path: string) {
        deleteSession();

        if (!providers.google) {
            throw new Error('Google provider not configured');
        }

        const { client_id } = providers.google;

        return createGoogleOAuthLoginUrl(redirect_uri, path, client_id);
    }

    /**
     * Generates a GitHub OAuth login URL and clears any existing session.
     *
     * @param redirect_uri OAuth redirect URI
     * @param path State parameter for the OAuth flow
     * @returns GitHub OAuth login URL
     * @throws Error if GitHub provider not configured
     */
    async function getGitHubLoginURL(redirect_uri: string, path: string) {
        deleteSession();

        if (!providers.github) {
            throw new Error('GitHub provider not configured');
        }

        const { client_id } = providers.github;

        return createGitHubOAuthLoginUrl(redirect_uri, path, client_id);
    }

    /**
     * Completes OAuth flow by exchanging authorization code for a session.
     *
     * @param code Authorization code from OAuth provider
     * @param redirect_uri OAuth redirect URI (must match login URL)
     * @param state OAuth state containing provider information
     * @returns Promise with error information
     */
    async function signInWithCode(
        code: string,
        redirect_uri: string,
        state: string | null = null
    ) {
        const provider = state ? JSON.parse(state).provider : null;

        if (!provider) {
            return {
                error: new Error('No provider specified in state')
            };
        }

        let oauthToken: string | null = null;

        if (providers.google && provider === 'google') {
            const { client_id, client_secret } = providers.google;

            const { data: googleData, error: exchangeError } =
                await exchangeCodeForGoogleIdToken(
                    code,
                    redirect_uri,
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
                    error: new Error('No exchange data!')
                };
            }

            oauthToken = googleData.id_token;
        } else if (providers.github && provider === 'github') {
            const { client_id, client_secret } = providers.github;

            const { data: githubData, error: exchangeError } =
                await exchangeCodeForGitHubIdToken(
                    code,
                    redirect_uri,
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
                    error: new Error('No exchange data!')
                };
            }

            oauthToken = githubData.access_token;
        }

        if (!oauthToken) {
            return {
                error: new Error('No OAuth token obtained')
            };
        }

        const { data: signInData, error: signInError } =
            await auth.signInWithProvider(oauthToken, redirect_uri);

        if (signInError) {
            return {
                error: signInError
            };
        }

        if (!signInData) {
            return {
                error: null
            };
        }

        const { data: sessionCookie, error: sessionError } =
            await adminAuth.createSessionCookie(signInData.idToken, {
                expiresIn: 60 * 60 * 24 * 5 * 1000
            });

        if (sessionError) {
            return {
                error: sessionError
            };
        }

        if (!sessionCookie) {
            return {
                error: new Error('No session cookie returned')
            };
        }

        saveSession(sessionName, sessionCookie, COOKIE_OPTIONS);

        return {
            error: null
        };
    }

    /**
     * Generates fresh Firebase client tokens for the authenticated user.
     *
     * @returns Promise with token data and error
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

        const { data: signJWTData, error: signJWTError } =
            await signJWTCustomToken(verifiedToken.sub, serviceAccount);

        if (signJWTError) {
            return {
                data: null,
                error: signJWTError
            };
        }

        if (!signJWTData) {
            return {
                data: null,
                error: new Error('No custom token signed')
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
        signInWithCode,
        getToken
    };
}
