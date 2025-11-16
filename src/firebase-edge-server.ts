import type {
    CookieOptions,
    GetSession,
    SetSession,
} from './auth/cookie-types.js';
import { FirebaseAdminAuth } from './auth/firebase-admin-auth.js';
import { FirebaseAuth } from './auth/firebase-auth.js';
import { signJWTCustomToken } from './auth/firebase-jwt.js';
import type { FirebaseConfig, ServiceAccount } from './auth/firebase-types.js';
import {
    createGoogleOAuthLoginUrl,
    exchangeCodeForGoogleIdToken,
} from './auth/google-oauth.js';

const DEFAULT_SESSION_NAME = '__session';

const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 5 * 1000,
} as CookieOptions;

/**
 * Official Firebase OAuth providers supported by Firebase Auth
 * @constant
 * @type {readonly string[]}
 */
export const OFFICIAL_FIREBASE_OAUTH_PROVIDERS: readonly string[] = [
    'google',
    'facebook',
    'apple',
    'twitter',
    'github',
    'microsoft',
    'yahoo',
    'playgames',
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
 * Creates a Firebase Edge Server instance with authentication and session management capabilities.
 *
 * This function sets up a complete Firebase authentication system that works in edge environments
 * like Cloudflare Workers, Vercel Edge Functions, and other serverless platforms.
 *
 * @param config - Configuration object for the Firebase Edge Server
 * @param config.serviceAccount - Firebase service account credentials for admin operations
 * @param config.firebaseConfig - Firebase project configuration (apiKey, authDomain, etc.)
 * @param config.providers - OAuth provider configurations (Google, Facebook, etc.)
 * @param config.cookies - Cookie management configuration for session handling
 * @param config.fetch - Optional custom fetch implementation (defaults to globalThis.fetch)
 *
 * @returns Object containing authentication methods and utilities
 *
 * @example
 * ```typescript
 * const server = createFirebaseEdgeServer({
 *   serviceAccount: {
 *     type: "service_account",
 *     project_id: "your-project-id",
 *     private_key_id: "...",
 *     private_key: "...",
 *     client_email: "...",
 *     client_id: "...",
 *     auth_uri: "...",
 *     token_uri: "...",
 *     auth_provider_x509_cert_url: "...",
 *     client_x509_cert_url: "..."
 *   },
 *   firebaseConfig: {
 *     apiKey: "your-api-key",
 *     authDomain: "your-project.firebaseapp.com",
 *     projectId: "your-project-id"
 *   },
 *   providers: {
 *     google: {
 *       client_id: "your-google-client-id",
 *       client_secret: "your-google-client-secret"
 *     }
 *   },
 *   cookies: {
 *     getSession: (name) => getCookie(name),
 *     saveSession: (name, value, options) => setCookie(name, value, options)
 *   }
 * });
 *
 * // Using guard clauses for clean error handling
 * const { data: user, error } = await server.getUser();
 * if (error) return handleError(error);
 * if (!user) return redirectToLogin();
 *
 * // User is authenticated, proceed with protected logic
 * console.log('Authenticated user:', user.email);
 * ```
 */
export function createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig,
    providers,
    cookies,
    fetch,
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
     * Deletes the current user session by clearing the session cookie.
     *
     * This is an internal helper function used by signOut and error handlers to ensure
     * clean session management when authentication fails or users sign out.
     *
     * @internal
     */
    function deleteSession() {
        saveSession(sessionName, '', {
            ...COOKIE_OPTIONS,
            maxAge: 0,
        });
    }

    /**
     * Signs out the current user by deleting their session cookie.
     *
     * This method only removes the local session and does not revoke the user's Firebase tokens.
     * For complete logout, consider also calling Firebase client-side signOut if needed.
     *
     * @example
     * ```typescript
     * // Simple sign out
     * server.signOut();
     *
     * // With redirect after sign out
     * server.signOut();
     * return redirect('/login');
     * ```
     */
    function signOut() {
        deleteSession();
        return;
    }

    /**
     * Retrieves the current authenticated user's information from their session.
     *
     * Validates the session cookie and returns the decoded user token. If the session
     * is invalid or expired, automatically cleans up the session cookie.
     *
     * @param checkRevoked - Whether to check if the user's token has been revoked (default: false)
     * @returns Promise resolving to user data and error information
     *
     * @example
     * ```typescript
     * // Using guard clauses for clean error handling
     * const { data: user, error } = await server.getUser();
     * if (error) {
     *   console.error('Authentication error:', error);
     *   return redirect('/login');
     * }
     *
     * if (!user) {
     *   console.log('No user session found');
     *   return redirect('/login');
     * }
     *
     * // User is authenticated, proceed safely
     * console.log('User ID:', user.sub);
     * console.log('Email:', user.email);
     * console.log('Email verified:', user.email_verified);
     *
     * // Check for revoked tokens in sensitive operations
     * const { data: verifiedUser, error: revokeError } = await server.getUser(true);
     * if (revokeError) return handleRevokedToken();
     * ```
     */
    async function getUser(checkRevoked: boolean = false) {
        const sessionCookie = await getSession(sessionName);

        if (!sessionCookie) {
            return {
                data: null,
                error: null,
            };
        }

        const { data: decodedToken, error: verifyError } =
            await adminAuth.verifySessionCookie(sessionCookie, checkRevoked);

        if (verifyError) {
            deleteSession();

            return {
                data: null,
                error: verifyError,
            };
        }

        if (!decodedToken) {
            deleteSession();

            return {
                data: null,
                error: null,
            };
        }

        return {
            data: decodedToken,
            error: null,
        };
    }

    /**
     * Generates a Google OAuth login URL for user authentication.
     *
     * Automatically clears any existing session before generating the URL to ensure
     * a clean authentication flow. The generated URL will redirect users to Google's
     * OAuth consent screen.
     *
     * @param redirect_uri - The URI to redirect to after Google authentication (must be registered in Google Console)
     * @param path - Additional path parameter for the OAuth flow state management
     * @returns Promise resolving to the Google OAuth login URL
     *
     * @throws {Error} If Google provider is not configured in the providers config
     *
     * @example
     * ```typescript
     * // Basic usage with guard clause
     * try {
     *   const loginUrl = await server.getGoogleLoginURL(
     *     'https://yourapp.com/auth/callback',
     *     '/dashboard'
     *   );
     *   return redirect(loginUrl);
     * } catch (error) {
     *   console.error('Google OAuth not configured:', error);
     *   return errorResponse('OAuth unavailable');
     * }
     *
     * // In a route handler
     * export async function GET(request: Request) {
     *   const url = new URL(request.url);
     *   const returnTo = url.searchParams.get('returnTo') || '/dashboard';
     *
     *   const loginUrl = await server.getGoogleLoginURL(
     *     `${url.origin}/auth/callback`,
     *     returnTo
     *   );
     *
     *   return redirect(loginUrl);
     * }
     * ```
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
     * Completes Google OAuth authentication by exchanging an authorization code for a session.
     *
     * This method should be called in your OAuth callback handler to complete the authentication
     * flow initiated by getGoogleLoginURL. It exchanges the authorization code for tokens,
     * creates a Firebase session, and sets the session cookie.
     *
     * @param code - The authorization code received from Google OAuth callback
     * @param redirect_uri - The redirect URI used in the OAuth flow (must match the one used in getGoogleLoginURL)
     * @returns Promise resolving to success/error information
     *
     * @example
     * ```typescript
     * // In your OAuth callback handler with guard clauses
     * export async function GET(request: Request) {
     *   const url = new URL(request.url);
     *   const code = url.searchParams.get('code');
     *   const state = url.searchParams.get('state');
     *
     *   // Guard clauses for validation
     *   if (!code) {
     *     console.error('No authorization code received');
     *     return redirect('/login?error=no_code');
     *   }
     *
     *   const { error } = await server.signInWithGoogleWithCode(
     *     code,
     *     `${url.origin}/auth/callback`
     *   );
     *
     *   if (error) {
     *     console.error('Sign in failed:', error.message);
     *     return redirect('/login?error=auth_failed');
     *   }
     *
     *   // Success - redirect to protected area
     *   const redirectTo = state || '/dashboard';
     *   return redirect(redirectTo);
     * }
     *
     * // Error handling with specific error types
     * const { error } = await server.signInWithGoogleWithCode(code, redirectUri);
     * if (error?.message.includes('provider not configured')) {
     *   return handleConfigError();
     * }
     * if (error?.message.includes('invalid_grant')) {
     *   return handleExpiredCode();
     * }
     * ```
     */
    async function signInWithGoogleWithCode(
        code: string,
        redirect_uri: string,
    ) {
        if (!providers.google) {
            return {
                error: new Error('Google provider not configured'),
            };
        }

        const { client_id, client_secret } = providers.google;

        const { data: exchangeData, error: exchangeError } =
            await exchangeCodeForGoogleIdToken(
                code,
                redirect_uri,
                client_id,
                client_secret,
                fetchImpl,
            );

        if (exchangeError) {
            return {
                error: exchangeError,
            };
        }

        if (!exchangeData) {
            return {
                error: new Error('No exchange data!'),
            };
        }

        const { data: signInData, error: signInError } =
            await auth.signInWithProvider(exchangeData.id_token, redirect_uri);

        if (signInError) {
            console.error(JSON.stringify(signInError));
            return {
                data: null,
                error: signInError,
            };
        }

        if (!signInData) {
            return {
                data: null,
                error: null,
            };
        }

        const { data: sessionCookie, error: sessionError } =
            await adminAuth.createSessionCookie(signInData.idToken, {
                expiresIn: 60 * 60 * 24 * 5 * 1000,
            });

        if (sessionError) {
            return {
                error: sessionError,
            };
        }

        if (!sessionCookie) {
            return {
                error: new Error('No session cookie returned'),
            };
        }

        saveSession(sessionName, sessionCookie, COOKIE_OPTIONS);

        return {
            error: null,
        };
    }

    /**
     * Generates a fresh Firebase access token for the currently authenticated user.
     *
     * This method creates new Firebase client tokens that can be used for authenticated
     * requests to Firebase services from the client-side. The tokens are generated using
     * the user's server-side session.
     *
     * @returns Promise resolving to token data (accessToken, refreshToken, etc.) and error information
     *
     * @example
     * ```typescript
     * // Using guard clauses for clean token handling
     * const { data: tokenData, error } = await server.getToken();
     * if (error) {
     *   console.error('Token generation failed:', error.message);
     *   return redirect('/login');
     * }
     *
     * if (!tokenData) {
     *   console.log('No user session for token generation');
     *   return redirect('/login');
     * }
     *
     * // Tokens are ready for client use
     * const response = {
     *   accessToken: tokenData.accessToken,
     *   refreshToken: tokenData.refreshToken,
     *   expiresIn: tokenData.expiresIn
     * };
     *
     * return json(response);
     *
     * // Using tokens for Firebase client initialization
     * const auth = getAuth(app);
     * await signInWithCustomToken(auth, tokenData.accessToken);
     *
     * // Guard against token refresh failures
     * if (tokenData.expiresIn < 300) { // Less than 5 minutes
     *   console.warn('Token expires soon, consider refreshing');
     * }
     * ```
     */
    async function getToken() {
        const { data: verifiedToken, error: verifyError } = await getUser();

        if (verifyError) {
            return {
                data: null,
                error: verifyError,
            };
        }

        if (!verifiedToken) {
            return {
                data: null,
                error: null,
            };
        }

        const { data: signJWTData, error: signJWTError } =
            await signJWTCustomToken(verifiedToken.sub, serviceAccount);

        if (signJWTError) {
            return {
                data: null,
                error: signJWTError,
            };
        }

        if (!signJWTData) {
            return {
                data: null,
                error: new Error('No custom token signed'),
            };
        }

        const { data: signInData, error: signInError } =
            await auth.signInWithCustomToken(signJWTData);

        if (signInError) {
            console.error(signInError);
            return {
                data: null,
                error: signInError,
            };
        }

        if (!signInData) {
            return {
                data: null,
                error: null,
            };
        }

        return {
            data: signInData,
            error: null,
        };
    }

    /**
     * Returns the complete Firebase Edge Server API with all authentication methods.
     *
     * @returns Object containing:
     * - `auth`: Firebase Auth instance for client-side operations
     * - `adminAuth`: Firebase Admin Auth instance for server-side operations
     * - `signOut`: Function to sign out the current user
     * - `getUser`: Function to get current user information with optional revocation checking
     * - `getGoogleLoginURL`: Function to generate Google OAuth login URL
     * - `signInWithGoogleWithCode`: Function to complete Google OAuth flow
     * - `getToken`: Function to get fresh Firebase tokens for client-side usage
     */
    return {
        auth,
        adminAuth,
        signOut,
        getUser,
        getGoogleLoginURL,
        signInWithGoogleWithCode,
        getToken,
    };
}
