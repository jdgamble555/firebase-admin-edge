import {
    signInWithCustomToken,
    signInWithIdp
} from './firebase-auth-endpoints.js';
import type { FirebaseConfig } from './firebase-types.js';
import { FirebaseEdgeError, ensureError } from './errors.js';
import { FirebaseAuthErrorInfo } from './auth-error-codes.js';

export class FirebaseAuth {
    constructor(
        private firebase_config: FirebaseConfig,
        private fetch?: typeof globalThis.fetch
    ) {}

    async signInWithProvider(
        oauthToken: string,
        requestUri: string,
        providerId = 'google.com'
    ) {
        try {
            const { data: signInData, error: signInError } =
                await signInWithIdp(
                    oauthToken,
                    requestUri,
                    providerId,
                    this.firebase_config.apiKey,
                    this.fetch
                );

            if (signInError) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAuthErrorInfo.AUTH_PROVIDER_SIGN_IN_FAILED,
                        {
                            cause: ensureError(signInError),
                            context: { providerId, requestUri }
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
                            context: { providerId, requestUri }
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
                        context: { providerId, requestUri }
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
}
