import { buildIdentityMetadataRequest } from './identity-write.js';
import type { UserMetadataRequest } from './user-import.js';
import {
    buildIdentityWriteRequest,
    type IdentityCreateData,
    type IdentityUpdateData,
    type IdentitySetData,
    type IdentityWriteResult
} from './identity-write.js';
import {
    getEnabledProviders,
    countAccounts,
    queryAccounts,
    createAuthEmulatorFetch,
    manageAuthConfig,
    generateEmailActionLink,
    sendPasswordResetEmailAdmin,
    deleteAccountsAdmin,
    importAccountsAdmin,
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
    resolveAuthEmulatorHost,
    type AuthEmulatorOptions
} from './auth-emulator.js';
export type { AuthEmulatorOptions } from './auth-emulator.js';
import { buildAuthConfigRequest, validateTenantId } from './auth-config.js';
import { ProjectConfigManager } from './project-config-manager.js';
import { TenantManager } from './tenant-manager.js';
import type {
    AuthConfigOperation,
    AuthProviderConfig,
    UpdateAuthProviderRequest,
    AuthProviderConfigFilter,
    ListProviderConfigResults
} from './auth-config-types.js';
export type * from './auth-config-types.js';
export { ProjectConfigManager } from './project-config-manager.js';
export { TenantManager } from './tenant-manager.js';
import {
    verifyAuthBlockingJWT,
    signJWTCustomToken,
    verifyJWT,
    verifySessionJWT
} from './firebase-jwt.js';
import type { DecodedAuthBlockingToken } from './auth-blocking-types.js';
export type {
    DecodedAuthBlockingToken,
    DecodedAuthBlockingUserRecord
} from './auth-blocking-types.js';
import type { GoogleTokenResponse, ServiceAccount } from './firebase-types.js';
import { getToken, type TokenResults } from './google-oauth.js';
import {
    FirebaseEdgeError,
    FirebaseAdminAuthErrorInfo,
    ensureError
} from './errors.js';
import type { CacheConfig } from './cache-types.js';
import {
    validateDeleteUsers,
    createBatchUserResult,
    type DeleteUsersResult,
    type UserImportResult
} from './user-batch.js';
import {
    prepareUserImport,
    type UserImportRecord,
    type UserImportOptions
} from './user-import.js';
export type {
    DeleteUsersResult,
    UserImportResult,
    FirebaseArrayIndexError
} from './user-batch.js';
export type {
    UserImportRecord,
    UserImportOptions,
    HashAlgorithmType,
    UserMetadataRequest,
    UserProviderRequest
} from './user-import.js';
import {
    createUserRecord,
    createGetUsersResult,
    type GetUsersResult,
    type ListUsersResult
} from './user-record.js';
import type { UserRecord } from './user-record.js';
import type { IdentityQueryOptions } from './identity-types.js';
import {
    buildUserRequest,
    buildCustomClaimsRequest,
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

import {
    buildEmailActionRequest,
    type ActionCodeSettings,
    type EmailActionType
} from './email-action-request.js';
export type { ActionCodeSettings } from './email-action-request.js';
export interface SessionCookieOptions {
    /** Session lifetime in milliseconds, between five minutes and fourteen days. */
    expiresIn: number;
}

export interface FirebaseAdminAuthOptions extends AuthEmulatorOptions {
    tenantId?: string;
    fetch?: typeof globalThis.fetch;
    cache?: CacheConfig;
    cacheName?: string;
}

/**
 * Firebase Admin Authentication handler for edge environments.
 * Provides server-side authentication operations using service account credentials.
 */
export class FirebaseAdminAuth {
    /** Read enabled standard provider configurations. @internal */
    async _getProviders() {
        try {
            const { error, data: token } = await this.getCachedToken();
            if (error) {
                return { data: null, error };
            }
            if (!token?.access_token) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            }
            return await getEnabledProviders(
                token.access_token,
                this.serviceAccountKey.project_id,
                this.tenantId,
                this.fetch
            );
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    /** Count accounts with the same native filter used by Identity queries. @internal */
    async _countUsers(
        filter?: IdentityQueryOptions['filter']
    ): Promise<{ data: number; error: null } | { data: null; error: Error }> {
        try {
            const { error: tokenError, data: token } =
                await this.getCachedToken();
            if (tokenError) {
                return { data: null, error: tokenError };
            }
            if (!token?.access_token) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            }
            return await countAccounts(
                token.access_token,
                this.serviceAccountKey.project_id,
                filter,
                this.tenantId,
                this.fetch
            );
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    /** Execute a validated Identity query using this client's token and tenant. @internal */
    async _queryUsers(
        options: IdentityQueryOptions
    ): Promise<
        { data: UserRecord[]; error: null } | { data: null; error: Error }
    > {
        try {
            const { error: tokenError, data: token } =
                await this.getCachedToken();
            if (tokenError) {
                return { data: null, error: tokenError };
            }
            if (!token?.access_token) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            }
            const { error, data } = await queryAccounts(
                token.access_token,
                this.serviceAccountKey.project_id,
                options,
                this.tenantId,
                this.fetch
            );
            if (error) {
                return { data: null, error };
            }
            return { data: data.map(createUserRecord), error: null };
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    readonly tenantId?: string;
    private fetch?: typeof globalThis.fetch;
    private cache?: CacheConfig;
    private cacheName?: string;

    /** Verify a blocking-event JWT. Audience matching follows the SDK's substring convention. */
    async _verifyAuthBlockingToken(
        token: string,
        audience?: string
    ): Promise<AdminResult<DecodedAuthBlockingToken>> {
        const result = await verifyAuthBlockingJWT(
            token,
            this.serviceAccountKey.project_id,
            audience,
            this.fetch,
            !!this.emulatorHost
        );
        if (result.error) return result;
        if (this.tenantId && result.data.tenant_id !== this.tenantId)
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_TENANT_ID_INVALID
                )
            };
        return result;
    }
    private readonly emulatorHost: string | null;
    private _cacheName = '__cache';
    private projectManager?: ProjectConfigManager;
    private tenants?: TenantManager;

    createProviderConfig(
        config: AuthProviderConfig
    ): Promise<AdminResult<AuthProviderConfig>> {
        return this.executeConfig({
            resource: 'provider',
            action: 'create',
            id: config?.providerId,
            properties: config
        });
    }

    getProviderConfig(
        providerId: string
    ): Promise<AdminResult<AuthProviderConfig>> {
        return this.executeConfig({
            resource: 'provider',
            action: 'get',
            id: providerId
        });
    }

    updateProviderConfig(
        providerId: string,
        config: UpdateAuthProviderRequest
    ): Promise<AdminResult<AuthProviderConfig>> {
        return this.executeConfig({
            resource: 'provider',
            action: 'update',
            id: providerId,
            properties: config
        });
    }

    deleteProviderConfig(providerId: string): Promise<AdminResult<void>> {
        return this.executeConfig({
            resource: 'provider',
            action: 'delete',
            id: providerId
        });
    }

    listProviderConfigs(
        filter: AuthProviderConfigFilter
    ): Promise<AdminResult<ListProviderConfigResults>> {
        return this.executeConfig({
            resource: 'provider',
            action: 'list',
            type: filter?.type,
            maxResults: filter?.maxResults,
            pageToken: filter?.pageToken
        });
    }

    projectConfigManager(): ProjectConfigManager {
        if (this.projectManager) return this.projectManager;
        this.projectManager = new ProjectConfigManager(
            this.executeConfig.bind(this)
        );
        return this.projectManager;
    }

    tenantManager(): TenantManager {
        if (this.tenants) return this.tenants;
        this.tenants = new TenantManager(
            this.executeConfig.bind(this),
            (tenantId) =>
                new FirebaseAdminAuth(this.serviceAccountKey, {
                    tenantId,
                    fetch: this.fetch,
                    cache: this.cache,
                    cacheName: this._cacheName,
                    emulatorHost: this.emulatorHost
                })
        );
        return this.tenants;
    }

    private async executeConfig<T>(
        operation: AuthConfigOperation
    ): Promise<AdminResult<T>> {
        try {
            buildAuthConfigRequest(operation);
            const { data: token, error } = await this.getCachedToken();
            if (error) return { data: null, error };
            if (!token?.access_token)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            return await manageAuthConfig<T>(
                this.serviceAccountKey.project_id,
                operation,
                token.access_token,
                this.fetch,
                this.tenantId
            );
        } catch (cause) {
            if (cause instanceof FirebaseEdgeError)
                return { data: null, error: cause };
            return {
                data: null,
                error: new FirebaseEdgeError(
                    {
                        code: 'auth/configuration-request-failed',
                        message: 'Authentication configuration request failed.'
                    },
                    { cause: ensureError(cause) }
                )
            };
        }
    }

    /**
     * Creates a new Firebase Admin Auth instance.
     *
     * @param serviceAccountKey Firebase service account credentials
     * @param options Optional constructor settings, including Auth emulator configuration.
     */
    constructor(
        private serviceAccountKey: ServiceAccount,
        options: FirebaseAdminAuthOptions = {}
    ) {
        const { tenantId, fetch, cache, cacheName } = options;
        if (tenantId !== undefined) {
            validateTenantId(tenantId);
        }

        this.tenantId = tenantId;
        this.fetch = fetch;
        this.cache = cache;
        this.cacheName = cacheName;

        this.emulatorHost = resolveAuthEmulatorHost(options.emulatorHost);
        if (this.emulatorHost) {
            this.fetch = createAuthEmulatorFetch(this.emulatorHost, this.fetch);
        }
        this._cacheName = this.cacheName || this._cacheName;
    }

    /**
     * Retrieves a cached service account token or fetches a new one.
     * Tokens are cached for 1 hour.
     *
     * @returns Promise with token data and error
     */
    private async getCachedToken(): Promise<TokenResults> {
        if (this.emulatorHost) {
            return {
                data: {
                    access_token: 'owner',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: '',
                    id_token: ''
                },
                error: null
            };
        }
        const cacheKey = `${this._cacheName}:auth:${this.serviceAccountKey.client_email}`;
        const cachedToken =
            await this.cache?.getCache<GoogleTokenResponse | null>(cacheKey);

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
            // Cache adapters accept milliseconds. Expire before the OAuth token does.
            const ttlMs = Math.max(0, (token.expires_in - 60) * 1000);
            if (Number.isFinite(ttlMs) && ttlMs > 0) {
                await this.cache.setCache(cacheKey, token, ttlMs);
            }
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

    /** @internal Write without fetching the user record afterward. */
    async _writeIdentityUser(
        uid: string | undefined,
        properties:
            | IdentityCreateData
            | IdentityUpdateData
            | IdentitySetData
            | UserMetadataRequest,
        mode: 'update' | 'set' | 'metadata' = 'update'
    ): Promise<AdminResult<IdentityWriteResult>> {
        if (mode !== 'update' && uid === undefined) {
            return {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-argument',
                    message: `${mode} requires an existing UID.`
                })
            };
        }
        if (uid !== undefined) {
            const error = validateUserUid(uid);
            if (error) {
                return { error, data: null };
            }
        }
        const { error: validationError, data: body } =
            mode === 'metadata'
                ? buildIdentityMetadataRequest(
                      properties as UserMetadataRequest
                  )
                : buildIdentityWriteRequest(
                      properties as
                          | IdentityCreateData
                          | IdentityUpdateData
                          | IdentitySetData,
                      uid === undefined ? 'create' : mode
                  );
        if (validationError) {
            return { error: validationError, data: null };
        }
        try {
            const { error: tokenError, data: token } =
                await this.getCachedToken();
            if (tokenError) {
                return { error: tokenError, data: null };
            }
            if (!token?.access_token) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            }
            const { customAttributes, ...createBody } = body!;
            const { error, data } =
                uid === undefined
                    ? await createAccountAdmin(
                          this.serviceAccountKey.project_id,
                          createBody,
                          token.access_token,
                          this.fetch,
                          this.tenantId
                      )
                    : await updateAccountAdmin(
                          this.serviceAccountKey.project_id,
                          uid,
                          body!,
                          token.access_token,
                          this.fetch,
                          this.tenantId
                      );
            if (error) {
                return { error: ensureError(error), data: null };
            }
            if (
                typeof data?.localId !== 'string' ||
                !data.localId ||
                (uid !== undefined && data.localId !== uid)
            ) {
                return {
                    data: null,
                    error: new FirebaseEdgeError({
                        code: 'auth/internal-error',
                        message: 'Identity write returned no matching UID.'
                    })
                };
            }
            if (uid === undefined && customAttributes !== undefined) {
                try {
                    const { error: claimsError } = await updateAccountAdmin(
                        this.serviceAccountKey.project_id,
                        data.localId,
                        { customAttributes },
                        token.access_token,
                        this.fetch,
                        this.tenantId
                    );
                    if (claimsError) {
                        throw claimsError;
                    }
                } catch (cause) {
                    const error = ensureError(cause);
                    return {
                        data: null,
                        error: new FirebaseEdgeError(
                            {
                                code:
                                    error instanceof FirebaseEdgeError
                                        ? error.code
                                        : 'auth/internal-error',
                                message: `User ${data.localId} was created, but setting custom claims failed: ${error.message}`
                            },
                            { cause: error, context: { uid: data.localId } }
                        )
                    };
                }
            }
            return { error: null, data: { uid: data.localId } };
        } catch (cause) {
            return { error: ensureError(cause), data: null };
        }
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

    /** Replace stored custom claims; pass null to clear all claims. */
    async setCustomUserClaims(
        uid: string,
        claims: object | null
    ): Promise<AdminResult<void>> {
        const uidError = validateUserUid(uid);
        if (uidError) return { data: null, error: uidError };
        const request = buildCustomClaimsRequest(claims);
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
                        FirebaseAdminAuthErrorInfo.ADMIN_SET_CUSTOM_CLAIMS_FAILED,
                        { cause: result.error }
                    )
                };
            if (!result.data?.localId)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_SET_CUSTOM_CLAIMS_FAILED
                    )
                };
            return { data: undefined, error: null };
        } catch (cause) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SET_CUSTOM_CLAIMS_FAILED,
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

    /** Delete up to 1000 users, reporting failures by original input index. */
    async deleteUsers(uids: string[]): Promise<AdminResult<DeleteUsersResult>> {
        const validationError = validateDeleteUsers(uids);
        if (validationError) return { data: null, error: validationError };
        if (uids.length === 0)
            return { data: createBatchUserResult([]), error: null };
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
            const result = await deleteAccountsAdmin(
                this.serviceAccountKey.project_id,
                uids,
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
            if (!result.data || typeof result.data !== 'object')
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_DELETE_USER_FAILED
                    )
                };
            return {
                data: createBatchUserResult(
                    uids.map((_, index) => index),
                    result.data.errors
                ),
                error: null
            };
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

    /** Import up to 1000 users, with local and API failures indexed to the original input. */
    async importUsers(
        users: UserImportRecord[],
        options?: UserImportOptions
    ): Promise<AdminResult<UserImportResult>> {
        const prepared = prepareUserImport(users, options, this.tenantId);
        if (prepared.error) return { data: null, error: prepared.error };
        const { body, indices, errors } = prepared.data;
        if (indices.length === 0)
            return {
                data: createBatchUserResult([], [], errors, 'import'),
                error: null
            };
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
            const result = await importAccountsAdmin(
                this.serviceAccountKey.project_id,
                body,
                token.access_token,
                this.fetch,
                this.tenantId
            );
            if (result.error)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_IMPORT_USERS_FAILED,
                        { cause: result.error }
                    )
                };
            if (!result.data || typeof result.data !== 'object')
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_IMPORT_USERS_FAILED
                    )
                };
            return {
                data: createBatchUserResult(
                    indices,
                    result.data.error,
                    errors,
                    'import'
                ),
                error: null
            };
        } catch (cause) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_IMPORT_USERS_FAILED,
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
        return this.lookupUser({ uid });
    }

    private async lookupUser(identifier: { uid: string } | { email: string }) {
        const validation = buildUsersLookupRequest([identifier]);
        if (validation.error) return { data: null, error: validation.error };
        try {
            const { data: token, error: tokenError } =
                await this.getCachedToken();
            if (tokenError) return { data: null, error: tokenError };
            if (!token?.access_token)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            const result = await getAccountInfo(
                identifier,
                token.access_token,
                this.serviceAccountKey.project_id,
                this.tenantId,
                this.fetch
            );
            if (result.error) return { data: null, error: result.error };
            if (!result.data)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND
                    )
                };
            return { data: result.data, error: null };
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
        return this.lookupUser({ email });
    }

    /** Look up a linked provider UID, or a primary email/phone identifier. */
    async getUserByProviderUid(
        providerId: string,
        uid: string
    ): Promise<AdminResult<UserRecord>> {
        const identifier: UserIdentifier =
            providerId === 'email'
                ? { email: uid }
                : providerId === 'phone'
                  ? { phoneNumber: uid }
                  : { providerId, providerUid: uid };
        const result = await this.getUsers([identifier]);
        if (result.error) return { data: null, error: result.error };
        const user = result.data.users[0];
        if (!user)
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND
                )
            };
        return { data: user, error: null };
    }

    /** Look up a user by their primary international phone number. */
    async getUserByPhoneNumber(
        phoneNumber: string
    ): Promise<AdminResult<UserRecord>> {
        const validation = buildUsersLookupRequest([{ phoneNumber }]);
        if (validation.error) return { data: null, error: validation.error };
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
            const result = await getAccountInfo(
                { phoneNumber },
                token.access_token,
                this.serviceAccountKey.project_id,
                this.tenantId,
                this.fetch
            );
            if (result.error) return { data: null, error: result.error };
            if (!result.data)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND
                    )
                };
            return { data: createUserRecord(result.data), error: null };
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
            this.fetch,
            !!this.emulatorHost
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

        if (!checkRevoked && !this.emulatorHost) {
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
                    userError.code ===
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND.code
                        ? FirebaseAdminAuthErrorInfo.ADMIN_USER_RECORD_NOT_FOUND
                        : FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED,
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
     * @param options Session cookie lifetime in milliseconds
     * @returns Promise with object containing session cookie string or null, and error if any
     */
    async createSessionCookie(
        idToken: string,
        options: SessionCookieOptions
    ): Promise<AdminResult<string>> {
        if (typeof idToken !== 'string' || !idToken.length)
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_ID_TOKEN_INVALID
                )
            };
        if (
            !options ||
            typeof options !== 'object' ||
            !Number.isFinite(options.expiresIn) ||
            options.expiresIn < 300000 ||
            options.expiresIn > 1209600000
        )
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_DURATION_INVALID
                )
            };
        try {
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

            if (!token?.access_token)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            const { data, error } = await createSessionCookie(
                idToken,
                token.access_token,
                this.serviceAccountKey.project_id,
                options.expiresIn,
                this.tenantId,
                this.fetch
            );

            if (error || !data) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_CREATE_FAILED,
                        {
                            cause: ensureError(
                                error ??
                                    new Error(
                                        'Firebase returned no session cookie.'
                                    )
                            )
                        }
                    )
                };
            }

            return {
                data,
                error: null
            };
        } catch (cause) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_CREATE_FAILED,
                    { cause: ensureError(cause) }
                )
            };
        }
    }

    /** Send a password-reset email for an Identity reference. @internal */
    async _sendPasswordResetEmail(
        email: string,
        settings?: ActionCodeSettings
    ) {
        const { error, data } = buildEmailActionRequest(
            'PASSWORD_RESET',
            email,
            settings
        );
        if (error) {
            return { error, data: null };
        }

        try {
            const { error: tokenError, data: token } =
                await this.getCachedToken();
            if (tokenError) {
                return { error: ensureError(tokenError), data: null };
            }
            if (!token?.access_token) {
                return {
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    ),
                    data: null
                };
            }

            return await sendPasswordResetEmailAdmin(
                this.serviceAccountKey.project_id,
                data,
                token.access_token,
                this.fetch,
                this.tenantId
            );
        } catch (cause) {
            return { error: ensureError(cause), data: null };
        }
    }

    /** Generate a password reset link to send through your own email service. */
    async generatePasswordResetLink(
        email: string,
        settings?: ActionCodeSettings
    ): Promise<AdminResult<string>> {
        return this.generateActionLink('PASSWORD_RESET', email, settings);
    }

    /** Generate an email verification link without sending an email. */
    async generateEmailVerificationLink(
        email: string,
        settings?: ActionCodeSettings
    ): Promise<AdminResult<string>> {
        return this.generateActionLink('VERIFY_EMAIL', email, settings);
    }

    /** Generate a link that verifies a new email before changing the account email. */
    async generateVerifyAndChangeEmailLink(
        email: string,
        newEmail: string,
        settings?: ActionCodeSettings
    ): Promise<AdminResult<string>> {
        return this.generateActionLink(
            'VERIFY_AND_CHANGE_EMAIL',
            email,
            settings,
            newEmail
        );
    }

    /** Generate an email sign-in link; action code settings are required. */
    async generateSignInWithEmailLink(
        email: string,
        settings: ActionCodeSettings
    ): Promise<AdminResult<string>> {
        return this.generateActionLink('EMAIL_SIGNIN', email, settings);
    }

    private async generateActionLink(
        requestType: EmailActionType,
        email: string,
        settings?: ActionCodeSettings,
        newEmail?: string
    ): Promise<AdminResult<string>> {
        const request = buildEmailActionRequest(
            requestType,
            email,
            settings,
            newEmail
        );
        if (request.error) return request;
        try {
            const { data: token, error: tokenError } =
                await this.getCachedToken();
            if (tokenError)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED,
                        { cause: ensureError(tokenError) }
                    )
                };
            if (!token?.access_token)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            const { data, error } = await generateEmailActionLink(
                this.serviceAccountKey.project_id,
                request.data,
                token.access_token,
                this.fetch,
                this.tenantId
            );
            if (error)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_EMAIL_ACTION_LINK_FAILED,
                        { cause: ensureError(error) }
                    )
                };
            return { data, error: null };
        } catch (cause) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_EMAIL_ACTION_LINK_FAILED,
                    { cause: ensureError(cause) }
                )
            };
        }
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
            this.fetch,
            !!this.emulatorHost
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

        if (!checkRevoked && !this.emulatorHost) {
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
                    userError.code ===
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_NOT_FOUND.code
                        ? FirebaseAdminAuthErrorInfo.ADMIN_USER_RECORD_NOT_FOUND
                        : FirebaseAdminAuthErrorInfo.ADMIN_USER_LOOKUP_FAILED,
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

        if (user.disabled)
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_USER_DISABLED
                )
            };
        if (user.validSince && data.auth_time < Number(user.validSince))
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_SESSION_COOKIE_REVOKED
                )
            };

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
        const uidError = validateUserUid(uid);
        if (uidError) return { data: null, error: uidError };
        try {
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

            if (!token?.access_token)
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        FirebaseAdminAuthErrorInfo.ADMIN_NO_TOKEN_RETURNED
                    )
                };
            const { data: revokeData, error: revokeError } =
                await revokeRefreshTokens(
                    this.serviceAccountKey.project_id,
                    uid,
                    token.access_token,
                    this.fetch,
                    this.tenantId
                );

            if (revokeError || !revokeData) {
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
        } catch (cause) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_REVOKE_TOKENS_FAILED,
                    { cause: ensureError(cause) }
                )
            };
        }
    }

    /**
     * Creates a custom Firebase authentication token for a given user.
     *
     * @param uid User ID to create token for
     * @param developerClaims Optional custom claims to include in the token
     * @returns Promise with object containing custom token string or null, and error if any
     */
    async createCustomToken(uid: string, developerClaims: object = {}) {
        const { data, error } = await signJWTCustomToken(
            uid,
            this.serviceAccountKey,
            developerClaims,
            this.tenantId,
            !!this.emulatorHost
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
