import {
    createAccountAdmin,
    updateAccountAdmin,
    deleteAccountAdmin,
    createSessionCookie,
    downloadAccount,
    getAccountInfo,
    getAccountsInfo,
    revokeRefreshTokens
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
import {
    createUserRecord,
    createGetUsersResult,
    type GetUsersResult,
    type ListUsersResult
} from './user-record.js';
import type { UserRecord } from './user-record.js';
import {
    buildUserRequest,
    buildUsersLookupRequest,
    type UserIdentifier,
    validateUserUid,
    type CreateRequest,
    type UpdateRequest
} from './user-request.js';
export type {
    UserIdentifier,
    UidIdentifier,
    EmailIdentifier,
    PhoneIdentifier,
    ProviderIdentifier,
    CreateRequest,
    UpdateRequest,
    UserProvider,
    CreatePhoneMultiFactorInfoRequest,
    UpdatePhoneMultiFactorInfoRequest
} from './user-request.js';
export type {
    GetUsersResult,
    ListUsersResult,
    UserRecord
} from './user-record.js';

type AdminResult<T> =
    | { data: T; error: null }
    | { data: null; error: FirebaseEdgeError };

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

    /** Create a user and return the complete user record. */
    async createUser(
        properties: CreateRequest
    ): Promise<AdminResult<UserRecord>> {
        const request = buildUserRequest(properties, 'create');
        if (request.error) return { data: null, error: request.error };
        try {
            const { data: token, error } = await this.getCachedToken();
            if (error) return { data: null, error };
            if (!token?.access_token)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            const result = await createAccountAdmin(
                this.serviceAccountKey.project_id,
                request.data,
                token.access_token,
                this.fetch,
                this.tenantId
            );
            if (result.error)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_CREATE_USER_FAILED,
                        { cause: result.error }
                    )
                };
            if (!result.data?.localId)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_CREATE_USER_FAILED
                    )
                };
            return await this.getManagedUser(
                result.data.localId,
                token.access_token
            );
        } catch (cause) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_CREATE_USER_FAILED,
                    { cause: ensureError(cause) }
                )
            };
        }
    }

    /** Update a user; null clears displayName, photoURL, or phoneNumber. */
    async updateUser(
        uid: string,
        properties: UpdateRequest
    ): Promise<AdminResult<UserRecord>> {
        const uidError = validateUserUid(uid);
        if (uidError) return { data: null, error: uidError };
        const request = buildUserRequest(properties, 'update');
        if (request.error) return { data: null, error: request.error };
        try {
            const { data: token, error } = await this.getCachedToken();
            if (error) return { data: null, error };
            if (!token?.access_token)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            const result = await updateAccountAdmin(
                this.serviceAccountKey.project_id,
                uid,
                request.data,
                token.access_token,
                this.fetch,
                this.tenantId
            );
            if (result.error)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_UPDATE_USER_FAILED,
                        { cause: result.error }
                    )
                };
            if (!result.data?.localId)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_UPDATE_USER_FAILED
                    )
                };
            return await this.getManagedUser(
                result.data.localId,
                token.access_token
            );
        } catch (cause) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_UPDATE_USER_FAILED,
                    { cause: ensureError(cause) }
                )
            };
        }
    }

    /** Delete one user. A successful deletion returns undefined data. */
    async deleteUser(uid: string): Promise<AdminResult<void>> {
        const uidError = validateUserUid(uid);
        if (uidError) return { data: null, error: uidError };
        try {
            const { data: token, error } = await this.getCachedToken();
            if (error) return { data: null, error };
            if (!token?.access_token)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            const result = await deleteAccountAdmin(
                this.serviceAccountKey.project_id,
                uid,
                token.access_token,
                this.fetch,
                this.tenantId
            );
            if (result.error)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_DELETE_USER_FAILED,
                        { cause: result.error }
                    )
                };
            return { data: undefined, error: null };
        } catch (cause) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_DELETE_USER_FAILED,
                    { cause: ensureError(cause) }
                )
            };
        }
    }

    /** Read back a complete record after a successful create or update. */
    private async getManagedUser(
        uid: string,
        token: string
    ): Promise<AdminResult<UserRecord>> {
        const { data, error } = await getAccountInfo(
            { uid },
            token,
            this.serviceAccountKey.project_id,
            this.tenantId,
            this.fetch
        );
        if (error) return { data: null, error };
        if (!data)
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_RECORD_NOT_FOUND
                )
            };
        return { data: createUserRecord(data), error: null };
    }

    /** Look up at most 100 identifiers, returning users and unmatched identifiers. */
    async getUsers(
        identifiers: UserIdentifier[]
    ): Promise<AdminResult<GetUsersResult>> {
        const request = buildUsersLookupRequest(identifiers);
        if (request.error) return { data: null, error: request.error };
        if (identifiers.length === 0)
            return { data: { users: [], notFound: [] }, error: null };
        try {
            const { data: token, error } = await this.getCachedToken();
            if (error) return { data: null, error };
            if (!token?.access_token)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            const result = await getAccountsInfo(
                request.data,
                token.access_token,
                this.serviceAccountKey.project_id,
                this.tenantId,
                this.fetch
            );
            if (result.error)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED,
                        { cause: result.error }
                    )
                };
            if (!result.data || typeof result.data !== 'object')
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED
                    )
                };
            return {
                data: createGetUsersResult(identifiers, result.data),
                error: null
            };
        } catch (cause) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED,
                    { cause: ensureError(cause) }
                )
            };
        }
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
     * Lists one page of users, using Firebase Admin's page size and token contract.
     * @param maxResults Page size (1–1000), defaults to 1000.
     * @param pageToken Token returned by the previous page.
     * @returns User records and an optional next page token, or a structured error.
     */
    async listUsers(
        maxResults = 1000,
        pageToken?: string
    ): Promise<
        | { data: ListUsersResult; error: null }
        | { data: null; error: FirebaseEdgeError }
    > {
        if (
            pageToken !== undefined &&
            (typeof pageToken !== 'string' || pageToken.length === 0)
        ) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_INVALID_PAGE_TOKEN
                )
            };
        }
        if (
            !Number.isInteger(maxResults) ||
            maxResults < 1 ||
            maxResults > 1000
        ) {
            return {
                data: null,
                error: new FirebaseEdgeError({
                    ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                    message:
                        'maxResults must be a positive integer that does not exceed 1000.'
                })
            };
        }

        try {
            const { data: token, error: tokenError } =
                await this.getCachedToken();
            if (tokenError) return { data: null, error: tokenError };
            if (!token?.access_token) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            }

            const { data, error } = await downloadAccount(
                token.access_token,
                this.serviceAccountKey.project_id,
                maxResults,
                pageToken,
                this.tenantId,
                this.fetch
            );
            if (error) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_LIST_USERS_FAILED,
                        {
                            cause: ensureError(error)
                        }
                    )
                };
            }
            if (!data || typeof data !== 'object') {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_LIST_USERS_FAILED
                    )
                };
            }
            return {
                data: {
                    users: (data.users ?? []).map(createUserRecord),
                    ...(data.nextPageToken !== undefined && {
                        pageToken: data.nextPageToken
                    })
                },
                error: null
            };
        } catch (error) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_LIST_USERS_FAILED,
                    { cause: ensureError(error) }
                )
            };
        }
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
     * Revokes a user's refresh tokens.
     *
     * @param uid User ID to revoke tokens for
     * @returns Promise with object containing revoke response data or null, and error if any
     */
    async revokeRefreshTokens(uid: string) {
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

        const { data: revokeData, error: revokeError } =
            await revokeRefreshTokens(
                this.serviceAccountKey.project_id,
                uid,
                token.access_token,
                this.fetch,
                this.tenantId
            );

        if (revokeError) {
            console.error('Error revoking tokens:', revokeError);
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_REVOKE_TOKENS_FAILED,
                    { cause: ensureError(revokeError) }
                )
            };
        }

        return {
            data: revokeData,
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
