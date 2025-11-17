import {
    signInWithCustomToken,
    signInWithIdp
} from './firebase-auth-endpoints.js';
import type { FirebaseConfig } from './firebase-types.js';

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
        const { data: signInData, error: signInError } = await signInWithIdp(
            oauthToken,
            requestUri,
            providerId,
            this.firebase_config.apiKey,
            this.fetch
        );

        if (signInError) {
            return {
                data: null,
                error: new Error(
                    `Failed to sign in with provider: ${signInError.message}`
                )
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

    async signInWithCustomToken(customToken: string) {
        const { data: signInData, error: signInError } =
            await signInWithCustomToken(
                customToken,
                this.firebase_config.apiKey,
                this.fetch
            );

        if (signInError) {
            return {
                data: null,
                error: new Error(
                    `Failed to sign in with custom token: ${signInError.message}`
                )
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
}
