import {
    signInWithCustomToken,
    signInWithIdp,
    linkWithOAuthCredential
} from './firebase-auth-endpoints.js';
import type { FirebaseConfig } from './firebase-types.js';
import { FirebaseEdgeError, ensureError } from './errors.js';
import { FirebaseAuthErrorInfo } from './auth-error-codes.js';

/**
 * Firebase Client Authentication handler for edge environments.
 * Provides client-side authentication operations using Firebase API.
 */
export class FirebaseAuth {
    /**
     * Creates a new Firebase Auth instance.
     *
     * @param firebase_config Firebase client configuration
     * @param requestUri OAuth callback URI
     * @param tenantId Optional tenant ID for multi-tenancy
     * @param fetch Optional custom fetch implementation
     */
    constructor(
        private firebase_config: FirebaseConfig,
        private requestUri: string,
        private tenantId?: string,
        private fetch?: typeof globalThis.fetch
    ) {}

    /**
     * Signs in a user with an OAuth provider token.
     *
     * @param oauthToken OAuth access token or ID token from the provider
     * @param providerId OAuth provider ID (defaults to 'google.com')
     * @returns Promise with object containing sign-in data or null, and error if any
     */
    async signInWithProvider(oauthToken: string, providerId = 'google.com') {
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
                            context: {
                                customToken:
                                    customToken.substring(0, 20) + '...'
                            }
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
                        context: {
                            customToken: customToken.substring(0, 20) + '...'
                        }
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
        providerToken: string,
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
                        FirebaseAuthErrorInfo.AUTH_PROVIDER_SIGN_IN_FAILED,
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
                    FirebaseAuthErrorInfo.AUTH_PROVIDER_SIGN_IN_FAILED,
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
}
