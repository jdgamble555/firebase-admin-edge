import {
    createSessionCookie,
    getAccountInfoByUid,
} from './firebase-auth-endpoints.js';
import {
    signJWTCustomToken,
    verifyJWT,
    verifySessionJWT,
} from './firebase-jwt.js';
import type { ServiceAccount } from './firebase-types.js';
import { getToken } from './google-oauth.js';

export class FirebaseAdminAuth {
    constructor(
        private serviceAccountKey: ServiceAccount,
        private fetch?: typeof globalThis.fetch,
    ) {}

    async getUser(uid: string) {
        // TODO: cache token and only refresh if expired

        const { data: token, error: getTokenError } = await getToken(
            this.serviceAccountKey,
            this.fetch,
        );

        if (getTokenError) {
            return {
                data: null,
                error: getTokenError,
            };
        }

        if (!token) {
            return {
                data: null,
                error: {
                    code: 500,
                    message: 'No token returned',
                    errors: [],
                },
            };
        }

        const { data, error } = await getAccountInfoByUid(
            uid,
            token.access_token,
            this.serviceAccountKey.project_id,
            this.fetch,
        );

        if (error) {
            return {
                data: null,
                error,
            };
        }

        return {
            data,
            error: null,
        };
    }

    async verifyIdToken(idToken: string, checkRevoked: boolean = false) {
        const { data: decodedIdToken, error: verifyError } = await verifyJWT(
            idToken,
            this.serviceAccountKey.project_id,
            this.fetch,
        );

        if (verifyError) {
            return {
                data: null,
                error: verifyError,
            };
        }

        if (!decodedIdToken) {
            return {
                data: null,
                error: {
                    message: 'Could not decode ID token!',
                    code: 'ERR_DECODE_ID_TOKEN',
                },
            };
        }

        if (!checkRevoked) {
            return {
                data: decodedIdToken,
                error: null,
            };
        }

        const { data: user, error: userError } = await this.getUser(
            decodedIdToken.sub,
        );

        if (userError) {
            return {
                data: null,
                error: userError,
            };
        }

        if (!user) {
            return {
                data: null,
                error: {
                    message: 'No user record found!',
                    code: 'ERR_NO_USER',
                },
            };
        }

        if (user.disabled) {
            return {
                data: null,
                error: {
                    message: 'User is disabled!',
                    code: 'ERR_USER_DISABLED',
                },
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
                    error: {
                        message: 'Token has been revoked!',
                        code: 'ERR_TOKEN_REVOKED',
                    },
                };
            }
        }

        return {
            data: decodedIdToken,
            error: null,
        };
    }

    async createSessionCookie(
        idToken: string,
        { expiresIn }: { expiresIn: number },
    ) {
        const { data: token, error: getTokenError } = await getToken(
            this.serviceAccountKey,
            this.fetch,
        );

        if (getTokenError) {
            return {
                data: null,
                error: getTokenError,
            };
        }

        if (!token) {
            return {
                data: null,
                error: {
                    code: 500,
                    message: 'No token returned',
                    errors: [],
                },
            };
        }

        const { data, error } = await createSessionCookie(
            idToken,
            token.access_token,
            this.serviceAccountKey.project_id,
            expiresIn,
            this.fetch,
        );

        if (error) {
            return {
                data: null,
                error,
            };
        }

        return {
            data,
            error: null,
        };
    }

    async verifySessionCookie(
        sessionCookie: string,
        checkRevoked: boolean = false,
    ) {
        const { data, error } = await verifySessionJWT(
            sessionCookie,
            this.serviceAccountKey.project_id,
            this.fetch,
        );

        if (error) {
            return {
                data: null,
                error,
            };
        }

        if (!checkRevoked) {
            return {
                data,
                error: null,
            };
        }

        const { data: user, error: userError } = await this.getUser(data!.sub);

        if (userError) {
            return {
                data: null,
                error: userError,
            };
        }

        if (!user) {
            return {
                data: null,
                error: {
                    message: 'No user record found!',
                    code: 'ERR_NO_USER',
                },
            };
        }

        return {
            data,
            error: null,
        };
    }

    async createCustomToken(uid: string, developerClaims: object = {}) {
        const { data, error } = await signJWTCustomToken(
            uid,
            this.serviceAccountKey,
            developerClaims,
        );

        if (error) {
            return {
                data: null,
                error,
            };
        }

        if (!data) {
            return {
                data: null,
                error: new Error('No custom token returned'),
            };
        }

        return {
            data,
            error: null,
        };
    }
}
