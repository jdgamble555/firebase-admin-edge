import {
    signInWithCustomToken,
    signInWithIdp,
    linkWithOAuthCredential
} from './firebase-auth-endpoints.js';
import type { FirebaseConfig } from './firebase-types.js';
import { FirebaseEdgeError, ensureError } from './errors.js';
import { FirebaseAuthErrorInfo } from './auth-error-codes.js';

export class FirebaseAuth {
    constructor(
        private firebase_config: FirebaseConfig,
        private requestUri: string,
        private tenantId?: string,
        private fetch?: typeof globalThis.fetch
    ) {}

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
