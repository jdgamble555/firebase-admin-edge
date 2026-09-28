import {
    type ProviderCredential,
    type ProviderAuthorizationOptions,
    type ProviderCallback
} from './provider-credential.js';
import {
    createAuthEmulatorFetch,
    createAuthUri,
    signInWithCustomToken,
    signInWithIdp,
    executeProviderSignIn,
    linkWithOAuthCredential,
    unlinkProvider,
    sendOobCode,
    confirmPasswordReset as resetPassword,
    applyActionCode as applyEmailCode,
    signInWithEmailLink as completeEmailLink
} from './firebase-auth-endpoints.js';
import {
    resolveAuthEmulatorHost,
    type AuthEmulatorOptions
} from './auth-emulator.js';
import type { FirebaseConfig } from './firebase-types.js';
import { FirebaseEdgeError, ensureError } from './errors.js';
import { FirebaseAuthErrorInfo } from './auth-error-codes.js';
import { buildEmailActionRequest } from './email-action-request.js';

export interface FirebaseAuthOptions extends AuthEmulatorOptions {
    tenantId?: string;
    fetch?: typeof globalThis.fetch;
}

/**
 * Firebase Client Authentication handler for edge environments.
 * Provides client-side authentication operations using Firebase API.
 */
export class FirebaseAuth {
    private tenantId?: string;
    private fetch?: typeof globalThis.fetch;

    async sendPasswordResetEmail(
        email: string,
        continueUrl = this.requestUri,
        locale?: string
    ) {
        try {
            return await sendOobCode(
                'PASSWORD_RESET',
                this.firebase_config.apiKey,
                { email, continueUrl, locale },
                this.tenantId,
                this.fetch
            );
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    async verifyBeforeUpdateEmail(
        idToken: string,
        newEmail: string,
        continueUrl = this.requestUri,
        locale?: string
    ) {
        try {
            return await sendOobCode(
                'VERIFY_AND_CHANGE_EMAIL',
                this.firebase_config.apiKey,
                { idToken, newEmail, continueUrl, locale },
                this.tenantId,
                this.fetch
            );
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    async confirmPasswordReset(oobCode: string, newPassword: string) {
        try {
            return await resetPassword(
                oobCode,
                newPassword,
                this.firebase_config.apiKey,
                this.tenantId,
                this.fetch
            );
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    async applyActionCode(oobCode: string) {
        try {
            return await applyEmailCode(
                oobCode,
                this.firebase_config.apiKey,
                this.tenantId,
                this.fetch
            );
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    /** Ask Firebase to deliver a sign-in email. */
    async sendSignInLinkToEmail(
        email: string,
        continueUrl: string,
        locale?: string
    ) {
        try {
            return await sendOobCode(
                'EMAIL_SIGNIN',
                this.firebase_config.apiKey,
                { email, continueUrl, locale },
                this.tenantId,
                this.fetch
            );
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    /** Exchange the email and one-time action code for Firebase tokens. */
    async signInWithEmailLink(email: string, oobCode: string) {
        const { error: validationError } = buildEmailActionRequest(
            'EMAIL_SIGNIN',
            email,
            {
                url: this.requestUri,
                handleCodeInApp: true
            }
        );
        if (validationError) {
            return { data: null, error: validationError };
        }
        if (typeof oobCode !== 'string' || !oobCode.trim()) {
            return {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-action-code',
                    message: 'An email sign-in code is required.'
                })
            };
        }
        try {
            return await completeEmailLink(
                oobCode,
                email,
                this.firebase_config.apiKey,
                undefined,
                this.tenantId,
                this.fetch
            );
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }
    /** Begin a Firebase-managed provider flow. Persist sessionId securely for the callback. */
    async createProviderAuthorization(
        providerId: string,
        options?: ProviderAuthorizationOptions
    ) {
        try {
            return await createAuthUri(
                this.requestUri,
                this.firebase_config.apiKey,
                this.tenantId,
                this.fetch,
                providerId,
                options
            );
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    /** Complete a provider callback; idToken links to an existing Firebase account. */
    async signInWithProviderCallback(
        callback: ProviderCallback,
        idToken?: string
    ) {
        try {
            return await executeProviderSignIn(
                { callback, idToken },
                this.firebase_config.apiKey,
                this.tenantId,
                this.fetch
            );
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    /**
     * Creates a new Firebase Auth instance.
     *
     * @param firebase_config Firebase client configuration
     * @param requestUri OAuth callback URI
     * @param options Optional constructor settings, including Auth emulator configuration.
     */
    constructor(
        private firebase_config: FirebaseConfig,
        private requestUri: string,
        options: FirebaseAuthOptions = {}
    ) {
        const { tenantId, fetch } = options;
        this.tenantId = tenantId;
        this.fetch = fetch;

        const emulatorHost = resolveAuthEmulatorHost(options.emulatorHost);
        if (emulatorHost) {
            this.fetch = createAuthEmulatorFetch(emulatorHost, this.fetch);
        }
    }

    /**
     * Signs in a user with an OAuth provider token.
     *
     * @param oauthToken OAuth access token or ID token from the provider
     * @param providerId OAuth provider ID (defaults to 'google.com')
     * @returns Promise with object containing sign-in data or null, and error if any
     */
    async signInWithProvider(
        oauthToken: string | ProviderCredential,
        providerId = 'google.com'
    ) {
        try {
            const { data: signInData, error: signInError } =
                await signInWithIdp(
                    oauthToken,
                    this.requestUri,
                    providerId,
                    this.firebase_config.apiKey,
                    this.tenantId,
                    this.fetch
                );

            if (signInError) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAuthErrorInfo.AUTH_PROVIDER_SIGN_IN_FAILED,
                        {
                            cause: ensureError(signInError),
                            context: { providerId, requestUri: this.requestUri }
                        }
                    )
                };
            }

            if (!signInData) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAuthErrorInfo.AUTH_PROVIDER_DATA_MISSING,
                        {
                            context: { providerId, requestUri: this.requestUri }
                        }
                    )
                };
            }

            return {
                data: signInData,
                error: null
            };
        } catch (err) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAuthErrorInfo.AUTH_PROVIDER_SIGN_IN_FAILED,
                    {
                        cause: ensureError(err),
                        context: { providerId, requestUri: this.requestUri }
                    }
                )
            };
        }
    }

    /**
     * Signs in a user with a custom Firebase authentication token.
     *
     * @param customToken Custom authentication token created by Firebase Admin SDK
     * @returns Promise with object containing sign-in data (idToken, refreshToken, expiresIn) or null, and error if any
     */
    async signInWithCustomToken(customToken: string) {
        if (typeof customToken !== 'string' || !customToken.trim()) {
            return {
                error: new FirebaseEdgeError(
                    FirebaseAuthErrorInfo.AUTH_INVALID_CUSTOM_TOKEN
                ),
                data: null
            };
        }
        try {
            const { data: signInData, error: signInError } =
                await signInWithCustomToken(
                    customToken,
                    this.firebase_config.apiKey,
                    this.tenantId,
                    this.fetch
                );

            if (signInError) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAuthErrorInfo.AUTH_INVALID_CUSTOM_TOKEN,
                        {
                            cause: ensureError(signInError),
                            context: { operation: 'signInWithCustomToken' }
                        }
                    )
                };
            }

            if (!signInData) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAuthErrorInfo.AUTH_PROVIDER_DATA_MISSING,
                        {
                            context: { operation: 'signInWithCustomToken' }
                        }
                    )
                };
            }

            return {
                data: signInData,
                error: null
            };
        } catch (err) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAuthErrorInfo.AUTH_CUSTOM_TOKEN_SIGN_FAILED,
                    {
                        cause: ensureError(err),
                        context: { operation: 'signInWithCustomToken' }
                    }
                )
            };
        }
    }

    /**
     * Links an OAuth credential to an existing user account.
     *
     * @param idToken Firebase ID token of the user to link
     * @param providerToken OAuth token from the provider to link
     * @param providerId OAuth provider ID (defaults to 'google.com')
     * @returns Promise with object containing linked account data or null, and error if any
     */
    async linkWithCredential(
        idToken: string,
        providerToken: string | ProviderCredential,
        providerId = 'google.com'
    ) {
        try {
            const { data: linkData, error: linkError } =
                await linkWithOAuthCredential(
                    idToken,
                    providerToken,
                    this.requestUri,
                    providerId,
                    this.firebase_config.apiKey,
                    this.tenantId,
                    this.fetch
                );

            if (linkError) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAuthErrorInfo.AUTH_PROVIDER_LINK_FAILED,
                        {
                            cause: ensureError(linkError),
                            context: { providerId, requestUri: this.requestUri }
                        }
                    )
                };
            }

            if (!linkData) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAuthErrorInfo.AUTH_PROVIDER_DATA_MISSING,
                        {
                            context: {
                                providerId,
                                requestUri: this.requestUri,
                                operation: 'linkWithCredential'
                            }
                        }
                    )
                };
            }

            return {
                data: linkData,
                error: null
            };
        } catch (err) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAuthErrorInfo.AUTH_PROVIDER_LINK_FAILED,
                    {
                        cause: ensureError(err),
                        context: {
                            providerId,
                            requestUri: this.requestUri,
                            operation: 'linkWithCredential'
                        }
                    }
                )
            };
        }
    }

    async unlink(idToken: string, providerId: string) {
        try {
            const { data: unlinkData, error: unlinkError } =
                await unlinkProvider(
                    idToken,
                    providerId,
                    this.firebase_config.apiKey,
                    this.tenantId,
                    this.fetch
                );

            if (unlinkError) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAuthErrorInfo.AUTH_PROVIDER_UNLINK_FAILED,
                        {
                            cause: ensureError(unlinkError),
                            context: { providerId }
                        }
                    )
                };
            }

            if (!unlinkData) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAuthErrorInfo.AUTH_PROVIDER_DATA_MISSING,
                        {
                            context: {
                                providerId,
                                operation: 'unlink'
                            }
                        }
                    )
                };
            }

            return {
                data: unlinkData,
                error: null
            };
        } catch (err) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAuthErrorInfo.AUTH_PROVIDER_UNLINK_FAILED,
                    {
                        cause: ensureError(err),
                        context: {
                            providerId,
                            requestUri: this.requestUri,
                            operation: 'unlink'
                        }
                    }
                )
            };
        }
    }
}
