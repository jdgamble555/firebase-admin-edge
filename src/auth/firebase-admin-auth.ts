import {
    createSessionCookie,
    getAccountInfoByUid
} from './firebase-auth-endpoints.js';
import {
    signJWTCustomToken,
    verifyJWT,
    verifySessionJWT
} from './firebase-jwt.js';
import type { ServiceAccount } from './firebase-types.js';
import { getToken } from './google-oauth.js';

export class FirebaseAdminAuth {
    constructor(
        private serviceAccountKey: ServiceAccount,
        private fetch?: typeof globalThis.fetch
    ) {}

    async getUser(uid: string) {
        // TODO: cache token and only refresh if expired

        const { data: token, error: getTokenError } = await getToken(
            this.serviceAccountKey,
            this.fetch
        );

        if (getTokenError) {
            return {
                data: null,
                error: getTokenError
            };
        }

        if (!token) {
            return {
                data: null,
                error: new Error('No token returned')
            };
        }

        const { data, error } = await getAccountInfoByUid(
            uid,
            token.access_token,
            this.serviceAccountKey.project_id,
            this.fetch
        );

        if (error) {
            return {
                data: null,
                error
            };
        }

        return {
            data,
            error: null
        };
    }

    async verifyIdToken(idToken: string, checkRevoked: boolean = false) {
        const { data: decodedIdToken, error: verifyError } = await verifyJWT(
            idToken,
            this.serviceAccountKey.project_id,
            this.fetch
        );

        if (verifyError) {
            return {
                data: null,
                error: new Error(
                    `Failed to verify ID token: ${verifyError.message}`
                )
            };
        }

        if (!decodedIdToken) {
            return {
                data: null,
                error: new Error('Failed to decode ID token')
            };
        }

        if (!checkRevoked) {
            return {
                data: decodedIdToken,
                error: null
            };
        }

        const { data: user, error: userError } = await this.getUser(
            decodedIdToken.sub
        );

        if (userError) {
            return {
                data: null,
                error: new Error(`Failed to get user: ${userError.message}`)
            };
        }

        if (!user) {
            return {
                data: null,
                error: new Error('No user record found!')
            };
        }

        if (user.disabled) {
            return {
                data: null,
                error: new Error(
                    'The user account has been disabled by an administrator.'
                )
            };
        }

        if (user.tokensValidAfterTime) {
            // Get the ID token authentication time and convert to milliseconds UTC.
            const authTimeUtc = decodedIdToken!.auth_time * 1000;

            // Get user tokens valid after time in milliseconds UTC.
            const validSinceUtc = new Date(user.tokensValidAfterTime).getTime();

            // Check if authentication time is older than valid since time.

            if (authTimeUtc < validSinceUtc) {
                return {
                    data: null,
                    error: new Error('The token has been revoked.')
                };
            }
        }

        return {
            data: decodedIdToken,
            error: null
        };
    }

    async createSessionCookie(
        idToken: string,
        { expiresIn }: { expiresIn: number }
    ) {
        const { data: token, error: getTokenError } = await getToken(
            this.serviceAccountKey,
            this.fetch
        );

        if (getTokenError) {
            return {
                data: null,
                error: new Error(
                    `Failed to get token: ${getTokenError.message}`
                )
            };
        }

        if (!token) {
            return {
                data: null,
                error: new Error('No token returned')
            };
        }

        const { data, error } = await createSessionCookie(
            idToken,
            token.access_token,
            this.serviceAccountKey.project_id,
            expiresIn,
            this.fetch
        );

        if (error) {
            return {
                data: null,
                error: new Error(
                    `Failed to create session cookie: ${error.message}`
                )
            };
        }

        return {
            data,
            error: null
        };
    }

    async verifySessionCookie(
        sessionCookie: string,
        checkRevoked: boolean = false
    ) {
        const { data, error } = await verifySessionJWT(
            sessionCookie,
            this.serviceAccountKey.project_id,
            this.fetch
        );

        if (error) {
            return {
                data: null,
                error: new Error(
                    `Failed to verify session cookie: ${error.message}`
                )
            };
        }

        if (!checkRevoked) {
            return {
                data,
                error: null
            };
        }

        const { data: user, error: userError } = await this.getUser(data!.sub);

        if (userError) {
            return {
                data: null,
                error: new Error(`Failed to get user: ${userError.message}`)
            };
        }

        if (!user) {
            return {
                data: null,
                error: new Error('No user record found!')
            };
        }

        return {
            data,
            error: null
        };
    }

    async createCustomToken(uid: string, developerClaims: object = {}) {
        const { data, error } = await signJWTCustomToken(
            uid,
            this.serviceAccountKey,
            developerClaims
        );

        if (error) {
            return {
                data: null,
                error
            };
        }

        if (!data) {
            return {
                data: null,
                error: new Error('No custom token returned')
            };
        }

        return {
            data,
            error: null
        };
    }
}
