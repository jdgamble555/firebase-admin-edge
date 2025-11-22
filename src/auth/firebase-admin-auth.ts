import {
    createSessionCookie,
    getAccountInfo
} from './firebase-auth-endpoints.js';
import {
    signJWTCustomToken,
    verifyJWT,
    verifySessionJWT
} from './firebase-jwt.js';
import type { GoogleTokenResponse, ServiceAccount } from './firebase-types.js';
import { getToken, type TokenResults } from './google-oauth.js';
import {
    FirebaseEdgeError,
    FirebaseAdminAuthErrorInfo,
    ensureError
} from './errors.js';
import type { CacheConfig } from './cache-types.js';

/**
 * Firebase Admin Authentication handler for edge environments.
 * Provides server-side authentication operations using service account credentials.
 */
export class FirebaseAdminAuth {
    private _cacheName = '__cache';

    /**
     * Creates a new Firebase Admin Auth instance.
     *
     * @param serviceAccountKey Firebase service account credentials
     * @param tenantId Optional tenant ID for multi-tenancy
     * @param fetch Optional custom fetch implementation
     * @param cache Optional cache implementation for token caching
     * @param cacheName Optional cache key name (defaults to '__cache')
     */
    constructor(
        private serviceAccountKey: ServiceAccount,
        private tenantId?: string,
        private fetch?: typeof globalThis.fetch,
        private cache?: CacheConfig,
        private cacheName?: string
    ) {
        this._cacheName = this.cacheName || this._cacheName;
    }

    /**
     * Retrieves a cached service account token or fetches a new one.
     * Tokens are cached for 1 hour.
     *
     * @returns Promise with token data and error
     */
    private async getCachedToken(): Promise<TokenResults> {
        const cachedToken =
            await this.cache?.getCache<GoogleTokenResponse | null>(
                this._cacheName
            );

        if (cachedToken) {
            return {
                data: cachedToken,
                error: null
            };
        }

        const { data: token, error: getTokenError } = await getToken(
            this.serviceAccountKey,
            this.fetch
        );

        if (token && this.cache) {
            // Google tokens are valid for 1 hour
            this.cache?.setCache('token', token, 3600);
        }

        if (getTokenError) {
            return {
                data: null,
                error: getTokenError
            };
        }

        return {
            data: token,
            error: null
        };
    }

    /**
     * Retrieves user account information by UID.
     *
     * @param uid User ID to look up
     * @returns Promise with object containing user data or null, and error if any
     */
    async getUser(uid: string) {
        const { data: token, error: tokenError } = await this.getCachedToken();

        if (tokenError) {
            return {
                data: null,
                error: tokenError
            };
        }

        const { data, error } = await getAccountInfo(
            { uid },
            token!.access_token,
            this.serviceAccountKey.project_id,
            this.tenantId,
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

    /**
     * Retrieves user account information by email address.
     *
     * @param email Email address to look up
     * @returns Promise with object containing user data or null, and error if any
     */
    async getUserByEmail(email: string) {
        const { data: token, error: tokenError } = await this.getCachedToken();

        if (tokenError) {
            return {
                data: null,
                error: tokenError
            };
        }

        const { data, error } = await getAccountInfo(
            { email },
            token.access_token,
            this.serviceAccountKey.project_id,
            this.tenantId,
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

    /**
     * Verifies a Firebase ID token and returns the decoded payload.
     * Optionally checks if the token has been revoked.
     *
     * @param idToken Firebase ID token to verify
     * @param checkRevoked Whether to check if token has been revoked (defaults to false)
     * @returns Promise with object containing decoded token payload or null, and error if any
     */
    async verifyIdToken(idToken: string, checkRevoked: boolean = false) {
        const { data: decodedIdToken, error: verifyError } = await verifyJWT(
            idToken,
            this.serviceAccountKey.project_id,
            this.fetch
        );

        if (verifyError) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_VERIFY_FAILED,
                    { cause: ensureError(verifyError) }
                )
            };
        }

        if (!decodedIdToken) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_DECODE_FAILED
                )
            };
        }

        // Validate tenant ID if specified
        if (this.tenantId) {
            const tokenTenantId = decodedIdToken.firebase?.tenant;
            if (tokenTenantId !== this.tenantId) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_TENANT_ID_INVALID,
                        {
                            context: {
                                tokenTenantId,
                                expectedTenantId: this.tenantId
                            }
                        }
                    )
                };
            }
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
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED,
                    { cause: ensureError(userError) }
                )
            };
        }

        if (!user) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_RECORD_NOT_FOUND
                )
            };
        }

        if (user.disabled) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_DISABLED
                )
            };
        }

        if (user.validSince) {
            const validSinceSeconds = Number(user.validSince);
            const authTimeSeconds = decodedIdToken!.auth_time;

            if (authTimeSeconds < validSinceSeconds) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_REVOKED
                    )
                };
            }
        }

        return {
            data: decodedIdToken,
            error: null
        };
    }

    /**
     * Creates a session cookie from a Firebase ID token.
     *
     * @param idToken Firebase ID token to convert to session cookie
     * @param expiresIn_ms Session cookie expiration time in milliseconds
     * @returns Promise with object containing session cookie string or null, and error if any
     */
    async createSessionCookie(idToken: string, expiresIn_ms: number) {
        const { data: token, error: getTokenError } =
            await this.getCachedToken();

        if (getTokenError) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED,
                    { cause: getTokenError }
                )
            };
        }

        const { data, error } = await createSessionCookie(
            idToken,
            token.access_token,
            this.serviceAccountKey.project_id,
            expiresIn_ms,
            this.tenantId,
            this.fetch
        );

        if (error) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_CREATE_FAILED,
                    { cause: ensureError(error) }
                )
            };
        }

        return {
            data,
            error: null
        };
    }

    /**
     * Verifies a Firebase session cookie and returns the decoded payload.
     * Optionally checks if the token has been revoked.
     *
     * @param sessionCookie Session cookie to verify
     * @param checkRevoked Whether to check if token has been revoked (defaults to false)
     * @returns Promise with object containing decoded session payload or null, and error if any
     */
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
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_VERIFY_FAILED,
                    { cause: ensureError(error) }
                )
            };
        }

        if (!data) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_VERIFY_FAILED
                )
            };
        }

        // Validate tenant ID if specified
        if (this.tenantId) {
            const tokenTenantId = data.firebase?.tenant;
            if (tokenTenantId !== this.tenantId) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_TENANT_ID_INVALID,
                        {
                            context: {
                                tokenTenantId,
                                expectedTenantId: this.tenantId
                            }
                        }
                    )
                };
            }
        }

        if (!checkRevoked) {
            return {
                data,
                error: null
            };
        }

        const { data: user, error: userError } = await this.getUser(data.sub);

        if (userError) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED,
                    { cause: ensureError(userError) }
                )
            };
        }

        if (!user) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_RECORD_NOT_FOUND
                )
            };
        }

        return {
            data,
            error: null
        };
    }

    /**
     * Creates a custom Firebase authentication token for a given user.
     *
     * @param uid User ID to create token for
     * @param developerClaims Optional custom claims to include in the token
     * @returns Promise with object containing custom token string or null, and error if any
     */
    async createCustomToken(uid: string, developerClaims: object = {}) {
        const claims = this.tenantId
            ? { ...developerClaims, tenant_id: this.tenantId }
            : developerClaims;

        const { data, error } = await signJWTCustomToken(
            uid,
            this.serviceAccountKey,
            claims
        );

        if (error) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_CUSTOM_TOKEN_CREATE_FAILED,
                    { cause: ensureError(error) }
                )
            };
        }

        if (!data) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_CUSTOM_TOKEN_NO_DATA
                )
            };
        }

        return {
            data,
            error: null
        };
    }
}
