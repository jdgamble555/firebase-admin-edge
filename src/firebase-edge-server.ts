import {
    isLocalRedirectPath,
    parseProviderSession
} from './auth/provider-session.js';
import {
    resolveProviderId,
    providerCredentialFromResponse,
    FIREBASE_PROVIDER_IDS,
    type ProviderCredential,
    type ProviderAuthorizationOptions
} from './auth/provider-credential.js';
import type { CookieConfig, CookieOptions } from './auth/cookie-types.js';
import { FirebaseAdminAuth } from './auth/firebase-admin-auth.js';
import { Identity } from './auth/identity.js';
import { Firestore } from './db/firestore.js';
import { AppCheck } from './app-check/app-check.js';
import { Storage } from './storage/storage.js';
import { FirebaseAuth } from './auth/firebase-auth.js';
import { resolveAuthEmulatorHost } from './auth/auth-emulator.js';
import type {
    FirebaseConfig,
    ServiceAccount,
    FirebaseIdpSignInResponse
} from './auth/firebase-types.js';
import { FirebaseEdgeError, ensureError } from './auth/errors.js';
import { FirebaseEdgeServerErrorInfo } from './firebase-edge-errors.js';
import type { CacheConfig } from './auth/cache-types.js';
import {
    createEmailLinkState,
    readEmailLinkState,
    parseEmailActionLink,
    parseEmailSignInLink
} from './auth/email-link.js';
import { buildEmailActionRequest } from './auth/email-action-request.js';

export type EmailLinkOptions = {
    includeEmailInLink?: boolean;
    callbackUrl?: string;
    locale?: string;
};

export type SignInCallbackOptions = {
    email?: string;
    expiresInMs?: number;
    postBody?: string;
};

export type CallbackOptions = SignInCallbackOptions & {
    newPassword?: string;
    confirmPassword?: string;
};

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
type ProviderList = keyof typeof FIREBASE_PROVIDER_IDS;
export const OFFICIAL_FIREBASE_OAUTH_PROVIDERS: readonly ProviderList[] =
    Object.keys(FIREBASE_PROVIDER_IDS) as ProviderList[];

/**
 * Creates a Firebase Edge Server for authentication and session management in edge environments.
 *
 * @param config Configuration object
 * @param config.serviceAccount Firebase service account for admin operations
 * @param config.firebaseConfig Firebase client configuration
 * @param config.cookies Cookie management functions (getSession, saveSession)
 * @param config.redirectUri OAuth callback redirect URI
 * @param config.cache Optional cache implementation for token caching
 * @param config.cacheName Optional cache key name for token storage
 * @param config.cookieName Optional custom session cookie name (defaults to '__session')
 * @param config.cookieOptions Optional cookie configuration overrides
 * @param config.tenantId Optional Firebase Auth tenant ID for multi-tenancy
 * @param config.autoLinkProviders Optional flag to automatically link accounts with same email
 * @param config.fetch Optional custom fetch implementation
 * @param config.authEmulatorHost Auth emulator host:port; null forces production, undefined reads the environment.
 * @returns Object with auth, adminAuth, firestore, and session management methods
 */
export function createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig,
    cookies,
    cookieName,
    cookieOptions,
    cache,
    cacheName,
    tenantId,
    redirectUri,
    autoLinkProviders,
    fetch,
    authEmulatorHost
}: {
    serviceAccount: ServiceAccount;
    firebaseConfig: FirebaseConfig;
    cookies: CookieConfig;
    cache?: CacheConfig;
    cacheName?: string;
    cookieName?: string;
    cookieOptions?: Partial<CookieOptions>;
    redirectUri: string;
    tenantId?: string;
    autoLinkProviders?: boolean;
    fetch?: typeof globalThis.fetch;
    authEmulatorHost?: string | null;
}) {
    // Cookies
    const _cookieName = cookieName || '__session';

    const { getSession, saveSession } = cookies;

    const _cookieOptions = { ...COOKIE_OPTIONS, ...cookieOptions };

    // Fetch
    const fetchImpl = fetch ?? globalThis.fetch;

    const cacheImpl = cache ?? undefined;

    // Auth instances
    const authOptions = {
        emulatorHost: resolveAuthEmulatorHost(authEmulatorHost)
    };
    const auth = new FirebaseAuth(firebaseConfig, redirectUri, {
        tenantId,
        fetch: fetchImpl,
        ...authOptions
    });
    const adminAuth = new FirebaseAdminAuth(serviceAccount, {
        tenantId,
        fetch: fetchImpl,
        cache: cacheImpl,
        cacheName,
        ...authOptions
    });
    const firestore = new Firestore(serviceAccount, {
        fetch: fetchImpl,
        cache: cacheImpl,
        cacheName
    });
    const identity = new Identity(serviceAccount, {
        tenantId,
        fetch: fetchImpl,
        cache: cacheImpl,
        cacheName,
        ...authOptions
    });

    const appCheck = new AppCheck(serviceAccount, {
        fetch: fetchImpl,
        cache: cacheImpl,
        cacheName
    });
    const storage = new Storage(serviceAccount, {
        bucketName: firebaseConfig.storageBucket,
        fetch: fetchImpl,
        cache: cacheImpl,
        cacheName
    });

    /** Describe the confirmation form to render, without exchanging or consuming any code. */
    function getCallbackAction(url: URL) {
        try {
            const action = parseEmailActionLink(
                url,
                firebaseConfig.apiKey,
                tenantId
            );
            if (!action) return { data: null, error: null };
            return {
                data: {
                    hasLink: action.hasLink,
                    actionMode: action.actionMode
                },
                error: null
            };
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    /** Complete any supported callback after the framework has obtained user confirmation. */
    async function handleCallback(url: URL, options: CallbackOptions = {}) {
        try {
            const action = parseEmailActionLink(
                url,
                firebaseConfig.apiKey,
                tenantId
            );
            if (!action || action.actionMode === 'signIn') {
                const { error, data } = await signInWithCallback(url, options);
                if (error) return { data: null, error };
                return {
                    data: { type: 'redirect' as const, url: data },
                    error: null
                };
            }
            if (!action.hasLink || !action.code)
                return {
                    data: null,
                    error: new FirebaseEdgeError({
                        code: 'auth/invalid-action-code',
                        message: 'An email action code is required.'
                    })
                };
            if (
                action.actionMode === 'resetPassword' &&
                options.confirmPassword !== undefined &&
                options.newPassword !== options.confirmPassword
            )
                return {
                    data: null,
                    error: new FirebaseEdgeError({
                        code: 'auth/password-mismatch',
                        message: 'Passwords do not match.'
                    })
                };
            const { error } =
                action.actionMode === 'resetPassword'
                    ? await confirmPasswordReset(
                          action.code,
                          options.newPassword ?? ''
                      )
                    : await applyActionCode(action.code);
            if (error) return { data: null, error };
            return {
                data: {
                    type: 'complete' as const,
                    message:
                        action.actionMode === 'resetPassword'
                            ? 'Your password has been reset. You can sign in again.'
                            : 'Your email has been updated or verified. Please sign in again.'
                },
                error: null
            };
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    /** Send Firebase's password reset email using the configured callback. */
    async function sendPasswordResetEmail(email: string, locale?: string) {
        return auth.sendPasswordResetEmail(email, redirectUri, locale);
    }

    /** Reset a password and clear the local session after success. */
    async function confirmPasswordReset(oobCode: string, newPassword: string) {
        const { error, data } = await auth.confirmPasswordReset(
            oobCode,
            newPassword
        );
        if (error) return { error, data };
        signOut();
        return { error, data };
    }

    /** Verify a new email before changing the currently signed-in account. */
    async function verifyBeforeUpdateEmail(newEmail: string, locale?: string) {
        const { error: userError, data: userData } = await getUser(true);
        if (userError) return { data: null, error: userError };
        if (!userData)
            return {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/unauthenticated',
                    message: 'Sign in before changing your email.'
                })
            };
        // getToken exchanges a custom token, so enforce recency on the original session first.
        const age = Date.now() / 1000 - userData.auth_time;
        if (!Number.isFinite(age) || age < 0 || age > 300)
            return {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/requires-recent-login',
                    message:
                        'Sign out and sign in again before changing your email.'
                })
            };
        const { error: tokenError, data: tokenData } = await getToken();
        if (tokenError) return { data: null, error: tokenError };
        if (!tokenData?.idToken)
            return {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/unauthenticated',
                    message: 'Sign in before changing your email.'
                })
            };
        return auth.verifyBeforeUpdateEmail(
            tokenData.idToken,
            newEmail,
            redirectUri,
            locale
        );
    }

    /** Apply an email action and discard stale local session claims on success. */
    async function applyActionCode(oobCode: string) {
        const { error, data } = await auth.applyActionCode(oobCode);
        if (error) return { error, data };
        signOut();
        return { error, data };
    }

    /** Persist a successful Firebase login as the configured session cookie. */
    async function saveSignInSession(
        signInData: { idToken?: string },
        next: string,
        expiresIn_ms: number
    ) {
        const { idToken } = signInData;

        if (!idToken) {
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_ID_TOKEN
                )
            };
        }

        const { data: sessionCookie, error: sessionError } =
            await adminAuth.createSessionCookie(idToken, {
                expiresIn: expiresIn_ms
            });

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

        await saveSession(_cookieName, sessionCookie, _cookieOptions);

        return {
            data: next,
            error: null
        };
    }

    /** Send a magic link with an optional email inside encrypted continuation state. */
    async function sendSignInLinkToEmail(
        email: string,
        next = '/',
        options: EmailLinkOptions = {}
    ) {
        if (!isLocalRedirectPath(next))
            return {
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-continue-uri',
                    message: 'The next path must be a local absolute path.'
                })
            };
        const callbackUrl = options.callbackUrl ?? redirectUri;
        const { error: validatedError } = buildEmailActionRequest(
            'EMAIL_SIGNIN',
            email,
            {
                url: callbackUrl,
                handleCodeInApp: true
            }
        );
        if (validatedError) return { error: validatedError };
        try {
            const state = await createEmailLinkState(
                { next, ...(options.includeEmailInLink && { email }) },
                serviceAccount.private_key,
                firebaseConfig.projectId,
                tenantId
            );
            const continuation = new URL(callbackUrl);
            continuation.searchParams.set('emailLinkState', state);
            const { error } = await auth.sendSignInLinkToEmail(
                email,
                continuation.toString(),
                options.locale
            );
            if (error) return { error };
            return { data: { sent: true as const }, error: null };
        } catch (cause) {
            return { error: ensureError(cause) };
        }
    }

    /** Complete a magic link with explicit email or email carried in encrypted state. */
    async function signInWithEmailLink(
        url: URL,
        options: { email?: string; expiresInMs?: number } = {}
    ) {
        try {
            const link = parseEmailSignInLink(
                url,
                firebaseConfig.apiKey,
                tenantId
            );
            const state = await readEmailLinkState(
                link.state,
                serviceAccount.private_key,
                firebaseConfig.projectId,
                tenantId
            );
            const email = options.email ?? state.email;
            if (!email)
                return {
                    error: new FirebaseEdgeError({
                        code: 'auth/missing-email',
                        message:
                            'Enter the email address this sign-in link was sent to.'
                    })
                };
            if (state.email && options.email && state.email !== options.email)
                return {
                    error: new FirebaseEdgeError({
                        code: 'auth/invalid-email',
                        message: 'The email does not match this sign-in link.'
                    })
                };
            const { error, data } = await auth.signInWithEmailLink(
                email,
                link.code
            );
            if (error) return { error };
            return await saveSignInSession(
                data ?? {},
                state.next,
                options.expiresInMs ?? COOKIE_LIFETIME_SECONDS * 1000
            );
        } catch (cause) {
            return { error: ensureError(cause) };
        }
    }

    /** Begin a provider flow using the provider configuration in Firebase Console. */
    async function startProviderAuthorization(
        provider: string,
        next: string,
        intent: 'signin' | 'link',
        options?: ProviderAuthorizationOptions
    ) {
        const providerId = resolveProviderId(provider);
        if (providerId === 'playgames.google.com')
            throw new FirebaseEdgeError({
                code: 'auth/operation-not-supported-in-this-environment',
                message:
                    'Use a native Play Games server authorization code with signInWithProviderToken.'
            });
        if (!isLocalRedirectPath(next))
            throw new FirebaseEdgeError({
                code: 'auth/invalid-continue-uri',
                message: 'The next path must be a local absolute path.'
            });
        if (intent === 'link') {
            const { error: userError, data: userData } = await getUser();
            if (userError) throw userError;
            if (!userData)
                throw new FirebaseEdgeError({
                    code: 'auth/user-not-found',
                    message: 'Sign in before linking a provider.'
                });
        }
        const { error, data } = await auth.createProviderAuthorization(
            providerId,
            options
        );
        if (error) throw error;
        if (!data?.authUri || !data.sessionId)
            throw new FirebaseEdgeError({
                code: 'auth/internal-error',
                message:
                    'Firebase returned an incomplete authorization response.'
            });
        await saveSession(
            _cookieName + '_oauth',
            JSON.stringify({ sessionId: data.sessionId, next, intent }),
            {
                ..._cookieOptions,
                httpOnly: true,
                secure: true,
                sameSite: 'none',
                maxAge: 600
            }
        );
        if (intent === 'signin') deleteSession();
        return data.authUri;
    }

    async function getProviderLoginURL(
        provider: string,
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return startProviderAuthorization(provider, next, 'signin', options);
    }

    async function getProviderLinkURL(
        provider: string,
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return startProviderAuthorization(provider, next, 'link', options);
    }

    /** Complete GET or form POST callbacks from Firebase-managed provider authorization. */
    async function signInWithProviderCallback(
        url: URL,
        postBody?: string,
        expiresIn_ms = COOKIE_LIFETIME_SECONDS * 1000
    ) {
        const stored = await getSession(_cookieName + '_oauth');
        if (!stored)
            return {
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-credential',
                    message:
                        'The provider authorization session is missing or expired.'
                })
            };
        await saveSession(_cookieName + '_oauth', '', {
            ..._cookieOptions,
            maxAge: 0
        });
        const flow = parseProviderSession(stored);
        if (!flow)
            return {
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-credential',
                    message: 'Invalid provider authorization session.'
                })
            };
        let idToken: string | undefined;
        if (flow.intent === 'link') {
            const { error: tokenError, data: tokenData } = await getToken();
            if (tokenError) return { error: tokenError };
            if (!tokenData?.idToken)
                return {
                    error: new FirebaseEdgeError({
                        code: 'auth/user-not-found',
                        message: 'Sign in before linking a provider.'
                    })
                };
            idToken = tokenData.idToken;
        }
        const { error, data } = await auth.signInWithProviderCallback(
            { requestUri: url.toString(), sessionId: flow.sessionId, postBody },
            idToken
        );
        if (error) return { error };
        if (!data)
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_SIGN_IN_DATA
                )
            };
        const signInData = data;
        const { error: completedError, data: completedData } =
            flow.intent === 'link'
                ? { error, data }
                : await completeProviderSignIn(
                      signInData,
                      async (existingIdToken) => {
                          if (signInData.pendingToken)
                              return auth.signInWithProviderCallback(
                                  {
                                      requestUri: url.toString(),
                                      pendingToken: signInData.pendingToken
                                  },
                                  existingIdToken
                              );
                          try {
                              const { providerId, credential } =
                                  providerCredentialFromResponse(signInData);
                              return await auth.linkWithCredential(
                                  existingIdToken,
                                  credential,
                                  providerId
                              );
                          } catch (cause) {
                              return { error: ensureError(cause) };
                          }
                      }
                  );
        if (completedError) return { error: completedError };
        if (!completedData?.idToken)
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_ID_TOKEN
                )
            };
        return saveSignInSession(completedData, flow.next, expiresIn_ms);
    }

    async function getFacebookLoginURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLoginURL('facebook', next, options);
    }

    async function getFacebookLinkURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLinkURL('facebook', next, options);
    }

    async function getAppleLoginURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLoginURL('apple', next, options);
    }

    async function getAppleLinkURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLinkURL('apple', next, options);
    }

    async function getTwitterLoginURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLoginURL('twitter', next, options);
    }

    async function getTwitterLinkURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLinkURL('twitter', next, options);
    }

    async function getMicrosoftLoginURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLoginURL('microsoft', next, options);
    }

    async function getMicrosoftLinkURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLinkURL('microsoft', next, options);
    }

    async function getYahooLoginURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLoginURL('yahoo', next, options);
    }

    async function getYahooLinkURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLinkURL('yahoo', next, options);
    }

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

    /** Begin Google sign-in using the provider configured in Firebase Console. */
    async function getGoogleLoginURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLoginURL('google', next, options);
    }

    /** Begin GitHub sign-in using the provider configured in Firebase Console. */
    async function getGitHubLoginURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLoginURL('github', next, options);
    }
    /**
     * Signs a user in using an already-obtained provider token.
     *
     * @param provider Firebase provider slug or ID
     * @param oauthToken Provider token (Google `id_token` or GitHub `access_token`)
     * @returns Promise resolving to an object containing sign-in data and/or an error
     */

    async function signInWithProviderToken(
        provider: string,
        oauthToken: string | ProviderCredential
    ) {
        let providerId: string;
        try {
            providerId = resolveProviderId(provider);
        } catch (error) {
            return { data: null, error: error as FirebaseEdgeError };
        }

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

        return completeProviderSignIn(signInData, (idToken) =>
            auth.linkWithCredential(idToken, oauthToken, providerId)
        );
    }

    /** Resolve same-email collisions consistently for credential and managed flows. */
    async function completeProviderSignIn(
        signInData: FirebaseIdpSignInResponse,
        linkCredential: (idToken: string) => Promise<{
            data?: FirebaseIdpSignInResponse | null;
            error?: Error | null;
        }>
    ) {
        if (!signInData.needConfirmation)
            return { data: signInData, error: null };
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

        const { data, error: getEmailError } = await adminAuth.getUserByEmail(
            signInData.email
        );

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

        if (!customTokenData)
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_CUSTOM_TOKEN_SIGNED
                )
            };

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

        return linkCredential(customSignInData.idToken);
    }
    /**
     * Completes provider or magic-link sign-in and saves a session.
     *
     * @param url Full provider callback or email action URL
     * @param options Callback options, or a legacy numeric session duration in milliseconds
     * @returns Promise resolving to object with next redirect path and error if any
     */
    async function signInWithCallback(
        url: URL,
        options: number | SignInCallbackOptions = {}
    ): Promise<{ error: null; data: string } | { error: Error; data?: never }> {
        const settings =
            typeof options === 'number' ? { expiresInMs: options } : options;
        try {
            const action = parseEmailActionLink(
                url,
                firebaseConfig.apiKey,
                tenantId
            );
            if (action) return signInWithEmailLink(url, settings);
        } catch (cause) {
            return { error: ensureError(cause) };
        }
        return signInWithProviderCallback(
            url,
            settings.postBody,
            settings.expiresInMs
        );
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

        const { data: signJWTData, error: signJWTError } =
            await adminAuth.createCustomToken(verifiedToken.sub);

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

    /**
     * Unlinks a provider from the currently authenticated user.
     *
     * @param providerId Firebase provider ID (e.g. 'google.com', 'github.com')
     * @param expiresIn_ms Session cookie expiration time in milliseconds (defaults to 5 days)
     * @returns Promise resolving to the unlink response data and/or an error
     */
    async function unlinkProvider(
        provider: string,
        expiresIn_ms: number = COOKIE_LIFETIME_SECONDS * 1000
    ) {
        const { data: verifiedToken, error: verifyError } = await getToken();

        if (verifyError) {
            return {
                data: null,
                error: verifyError
            };
        }

        if (!verifiedToken?.idToken) {
            return {
                data: null,
                error: null
            };
        }

        const { data: unlinkData, error: unlinkError } = await auth.unlink(
            verifiedToken.idToken,
            provider
        );

        if (unlinkError) {
            return {
                data: null,
                error: unlinkError
            };
        }

        const { data: idToken, error: idTokenError } = await getToken();

        if (idTokenError) {
            return {
                error: idTokenError
            };
        }

        if (!idToken?.idToken) {
            return {
                error: new FirebaseEdgeError(
                    FirebaseEdgeServerErrorInfo.EDGE_NO_ID_TOKEN
                )
            };
        }

        const { data: sessionCookie, error: sessionError } =
            await adminAuth.createSessionCookie(idToken.idToken, {
                expiresIn: expiresIn_ms
            });

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

        await saveSession(_cookieName, sessionCookie, _cookieOptions);

        return {
            data: unlinkData,
            error: null
        };
    }

    /** Begin Google linking for the currently authenticated user. */
    async function getGoogleLinkURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLinkURL('google', next, options);
    }

    /** Begin GitHub linking for the currently authenticated user. */
    async function getGitHubLinkURL(
        next: string,
        options?: ProviderAuthorizationOptions
    ) {
        return getProviderLinkURL('github', next, options);
    }
    /**
     * Links an OAuth provider to the currently authenticated user.
     *
     * @param providerToken Provider token (Google `id_token` or GitHub `access_token`)
     * @param providerId Firebase provider ID (e.g. 'google.com', 'github.com')
     * @returns Promise resolving to link response data and/or an error
     */
    async function linkProvider(
        providerToken: string | ProviderCredential,
        providerId: string
    ) {
        const { data: verifiedToken, error: verifyError } = await getToken();

        if (verifyError) {
            return {
                data: null,
                error: verifyError
            };
        }

        if (!verifiedToken?.idToken) {
            return {
                data: null,
                error: null
            };
        }

        const { data: unlinkData, error: unlinkError } =
            await auth.linkWithCredential(
                verifiedToken.idToken,
                providerToken,
                providerId
            );

        if (unlinkError) {
            return {
                data: null,
                error: unlinkError
            };
        }

        return {
            data: unlinkData,
            error: null
        };
    }

    return {
        auth,
        adminAuth,
        firestore,
        identity,
        appCheck,
        storage,
        sendSignInLinkToEmail,
        getCallbackAction,
        handleCallback,
        sendPasswordResetEmail,
        confirmPasswordReset,
        verifyBeforeUpdateEmail,
        applyActionCode,
        signOut,
        getUser,
        getProviderLoginURL,
        getProviderLinkURL,
        signInWithProviderCallback,
        signInWithProviderToken,
        getFacebookLoginURL,
        getFacebookLinkURL,
        getAppleLoginURL,
        getAppleLinkURL,
        getTwitterLoginURL,
        getTwitterLinkURL,
        getMicrosoftLoginURL,
        getMicrosoftLinkURL,
        getYahooLoginURL,
        getYahooLinkURL,
        getGoogleLoginURL,
        getGitHubLoginURL,
        getGoogleLinkURL,
        getGitHubLinkURL,
        signInWithCallback,
        getToken,
        linkProvider,
        unlinkProvider
    };
}
