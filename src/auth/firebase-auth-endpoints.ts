import {
    providerCredentialBody,
    resolveProviderId,
    type ProviderCredential,
    type ProviderAuthorizationOptions,
    type ProviderCallback
} from './provider-credential.js';
import type {
    FirebaseCreateAuthUriResponse,
    FirebaseIdpSignInResponse,
    FirebaseRefreshTokenResponse,
    FirebaseRestError,
    FirebaseUpdateAccountResponse,
    UpdateAccountRequest,
    UserInfo
} from './firebase-types.js';
import { restFetch } from '../rest-fetch.js';
import { resolveAuthEmulatorHost } from './auth-emulator.js';

import type { JsonWebKey } from 'crypto';
import {
    mapFirebaseError,
    normalizeAdminEndpointError
} from './auth-endpoint-errors.js';
import { FirebaseEdgeError, ensureError } from './errors.js';
import type { ListUsersResponse } from './user-record.js';
import type { UsersLookupRequest } from './user-request.js';
import type { BatchUserError } from './user-batch.js';
import type { PreparedUserImport } from './user-import.js';
import {
    buildEmailActionRequest,
    type EmailActionRequest
} from './email-action-request.js';
import type {
    AuthConfigOperation,
    AuthConfigResult
} from './auth-config-types.js';
import {
    buildAuthConfigRequest,
    configUpdateMask,
    parseAuthConfigResponse
} from './auth-config.js';

/** Route Auth REST requests to an explicitly configured emulator. Other services keep their original URLs. @internal */
export function createAuthEmulatorFetch(
    host: string,
    fetchFn: typeof globalThis.fetch = globalThis.fetch
): typeof globalThis.fetch {
    const emulatorHost = resolveAuthEmulatorHost(host);
    if (!emulatorHost) throw new Error('An auth emulator host is required.');
    return (input, init) => {
        const url = new URL(
            input instanceof Request ? input.url : String(input)
        );
        if (
            ![
                'identitytoolkit.googleapis.com',
                'securetoken.googleapis.com'
            ].includes(url.hostname)
        )
            return fetchFn(input, init);
        const target = `http://${emulatorHost}/${url.hostname}${url.pathname}${url.search}`;
        const headers = new Headers(
            init?.headers ??
                (input instanceof Request ? input.headers : undefined)
        );
        if (headers.has('Authorization'))
            headers.set('Authorization', 'Bearer owner');
        if (input instanceof Request)
            return fetchFn(new Request(target, input), { ...init, headers });
        return fetchFn(target, { ...init, headers });
    };
}

/** Execute a configuration operation using the Identity Platform v2 API. @internal */
export async function manageAuthConfig<T>(
    projectId: string,
    operation: AuthConfigOperation,
    token: string,
    fetchFn?: typeof globalThis.fetch,
    tenantId?: string
): Promise<AuthConfigResult<T>> {
    try {
        const body = buildAuthConfigRequest(operation);
        const { resource, action, id } = operation;
        const providerType =
            operation.type ?? (id?.startsWith('oidc.') ? 'oidc' : 'saml');
        const collection =
            resource === 'project'
                ? 'config'
                : resource === 'tenant'
                  ? 'tenants'
                  : providerType === 'oidc'
                    ? 'oauthIdpConfigs'
                    : 'inboundSamlConfigs';
        const parent = createAdminIdentityURL(
            projectId,
            '',
            false,
            resource === 'provider' ? tenantId : undefined,
            'v2'
        );
        const suffix =
            action !== 'create' && action !== 'list' && resource !== 'project'
                ? `/${encodeURIComponent(id!)}`
                : '';
        const params: Record<string, string> = {};
        if (action === 'create' && resource === 'provider')
            params[
                providerType === 'oidc'
                    ? 'oauthIdpConfigId'
                    : 'inboundSamlConfigId'
            ] = id!;
        if (action === 'update')
            params.updateMask = configUpdateMask(body!).join(',');
        if (action === 'list') {
            params.pageSize = String(
                operation.maxResults ?? (resource === 'tenant' ? 1000 : 100)
            );
            if (operation.pageToken !== undefined)
                params.pageToken = operation.pageToken;
        }
        const method =
            action === 'create'
                ? 'POST'
                : action === 'update'
                  ? 'PATCH'
                  : action === 'delete'
                    ? 'DELETE'
                    : 'GET';
        const result = await restFetch<unknown, FirebaseRestError>(
            `${parent}/${collection}${suffix}`,
            {
                method,
                ...(body !== undefined && { body }),
                params,
                bearerToken: token,
                global: { fetch: fetchFn }
            }
        );
        if (result.error) {
            const apiError =
                typeof result.error === 'object'
                    ? result.error.error
                    : undefined;
            if (
                apiError &&
                (apiError.code === 404 ||
                    /CONFIGURATION_NOT_FOUND|TENANT_NOT_FOUND/.test(
                        apiError.message
                    ))
            )
                return {
                    data: null,
                    error: new FirebaseEdgeError({
                        code:
                            resource === 'tenant'
                                ? 'auth/tenant-not-found'
                                : 'auth/configuration-not-found',
                        message:
                            'The requested authentication configuration was not found.'
                    })
                };
            if (
                apiError &&
                (apiError.code === 409 ||
                    /CONFIGURATION_EXISTS|TENANT_EXISTS/.test(apiError.message))
            )
                return {
                    data: null,
                    error: new FirebaseEdgeError({
                        code: 'auth/configuration-exists',
                        message:
                            'The authentication configuration already exists.'
                    })
                };
            const error =
                typeof result.error === 'object' && result.error.error
                    ? mapFirebaseError(result.error.error)
                    : new FirebaseEdgeError(
                          {
                              code: 'auth/configuration-request-failed',
                              message: 'Configuration endpoint failed.'
                          },
                          { cause: ensureError(result.error) }
                      );
            return { data: null, error };
        }
        return {
            data: parseAuthConfigResponse(operation, result.data) as T,
            error: null
        };
    } catch (cause) {
        if (cause instanceof FirebaseEdgeError)
            return { data: null, error: cause };
        return {
            data: null,
            error: new FirebaseEdgeError(
                {
                    code: 'auth/configuration-request-failed',
                    message: 'Configuration endpoint failed.'
                },
                { cause: ensureError(cause) }
            )
        };
    }
}

/** Generate an email action link without sending an email. */
export async function generateEmailActionLink(
    projectId: string,
    body: EmailActionRequest,
    token: string,
    fetchFn?: typeof globalThis.fetch,
    tenantId?: string
) {
    const { data, error } = await restFetch<
        { oobLink: string },
        FirebaseRestError
    >(createAdminIdentityURL(projectId, 'sendOobCode', true, tenantId), {
        body,
        bearerToken: token,
        global: { fetch: fetchFn }
    });
    if (error)
        return {
            data: null,
            error: normalizeAdminEndpointError(error)
        };
    if (typeof data?.oobLink !== 'string' || !data.oobLink.length)
        return {
            data: null,
            error: new Error('Firebase returned no email action link.')
        };
    return { data: data.oobLink, error: null };
}

/** Delete a validated batch, including enabled users. Missing users count as successes. */
export async function deleteAccountsAdmin(
    projectId: string,
    uids: string[],
    token: string,
    fetchFn?: typeof globalThis.fetch,
    tenantId?: string
) {
    const url = createAdminIdentityURL(
        projectId,
        'batchDelete',
        true,
        tenantId
    );
    const { data, error } = await restFetch<
        { errors?: BatchUserError[] },
        FirebaseRestError
    >(url, {
        body: { localIds: uids, force: true },
        bearerToken: token,
        global: { fetch: fetchFn }
    });
    if (error)
        return {
            data: null,
            error: normalizeAdminEndpointError(error)
        };
    return { data, error: null };
}

/** Submit prepared import records and hash settings to the admin batch API. */
export async function importAccountsAdmin(
    projectId: string,
    body: PreparedUserImport['body'],
    token: string,
    fetchFn?: typeof globalThis.fetch,
    tenantId?: string
) {
    const url = createAdminIdentityURL(
        projectId,
        'batchCreate',
        true,
        tenantId
    );
    const { data, error } = await restFetch<
        { error?: BatchUserError[] },
        FirebaseRestError
    >(url, {
        body,
        bearerToken: token,
        global: { fetch: fetchFn }
    });
    if (error)
        return {
            data: null,
            error: normalizeAdminEndpointError(error)
        };
    return { data, error: null };
}

/** Look up a validated batch, allowing successful responses with no matching users. */
export async function getAccountsInfo(
    identifiers: UsersLookupRequest,
    token: string,
    projectId: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createAdminIdentityURL(projectId, 'lookup', true, tenantId);
    const { data, error } = await restFetch<
        ListUsersResponse,
        FirebaseRestError
    >(url, {
        body: identifiers,
        bearerToken: token,
        global: { fetch: fetchFn }
    });
    if (error)
        return {
            data: null,
            error: normalizeAdminEndpointError(error)
        };
    return { data, error: null };
}

// Functions

/**
 * Builds an Identity Toolkit Admin API URL.
 *
 * If a tenant ID is provided, the URL targets Identity Platform tenant resources.
 */
function createAdminIdentityURL(
    project_id: string,
    name: string,
    accounts = true,
    tenantId?: string,
    version = 'v1'
) {
    const action = name ? `:${name}` : '';
    if (tenantId) {
        // Use Identity Platform API for tenant-specific operations
        return `https://identitytoolkit.googleapis.com/${version}/projects/${encodeURIComponent(project_id)}/tenants/${encodeURIComponent(tenantId)}${accounts ? '/accounts' : ''}${action}`;
    }
    return `https://identitytoolkit.googleapis.com/${version}/projects/${encodeURIComponent(project_id)}${accounts ? '/accounts' : ''}${action}`;
}

/**
 * Builds a standard Firebase Auth REST API URL.
 *
 * Note: tenant ID is provided in the request body for these endpoints.
 */
function createIdentityURL(name: string) {
    // Standard Firebase Auth REST API - tenant ID goes in request body, not URL
    return `https://identitytoolkit.googleapis.com/v1/accounts:${name}`;
}

/**
 * Exchanges a refresh token for a new Firebase ID token.
 *
 * @param refreshToken Firebase refresh token.
 * @param key Firebase Web API key.
 * @param fetchFn Optional fetch implementation (useful for runtimes like edge).
 */
export async function refreshFirebaseIdToken(
    refreshToken: string,
    key: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = `https://securetoken.googleapis.com/v1/token`;

    const { data, error } = await restFetch<
        FirebaseRefreshTokenResponse,
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body: {
            grant_type: 'refresh_token',
            refresh_token: refreshToken
        },
        params: {
            key
        },
        form: true
    });

    return {
        data,
        error: error ? mapFirebaseError(error.error) : null
    };
}

/**
 * Creates an Auth URI to initiate an OAuth sign-in flow (Google by default).
 *
 * @param redirect_uri Redirect/continue URL.
 * @param key Firebase Web API key.
 * @param tenantId Optional tenant ID.
 * @param fetchFn Optional fetch implementation.
 */
export async function createAuthUri(
    redirect_uri: string,
    key: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch,
    providerId = 'google.com',
    options: ProviderAuthorizationOptions = {}
) {
    const url = createIdentityURL('createAuthUri');
    const resolvedProviderId = resolveProviderId(providerId);

    const body = {
        continueUri: redirect_uri,
        providerId: resolvedProviderId,
        ...(resolvedProviderId === 'google.com' && {
            authFlowType: 'CODE_FLOW'
        }),
        ...(options.addScopes?.length && {
            oauthScope: options.addScopes.join(' ')
        }),
        ...(options.customParameters && {
            customParameter: options.customParameters
        }),
        ...(tenantId && { tenantId })
    };

    const { data, error } = await restFetch<
        FirebaseCreateAuthUriResponse,
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body,
        params: {
            key
        }
    });

    return {
        data,
        error: error ? mapFirebaseError(error.error) : null
    };
}

/**
 * Signs a user in via an identity provider (Google/GitHub/etc.) using the IdP token.
 *
 * @param providerIdToken The IdP token (GitHub access token or OIDC ID token).
 * @param requestUri The origin/URL of the sign-in request.
 * @param providerId Provider ID (e.g. "google.com", "github.com").
 * @param key Firebase Web API key.
 * @param tenantId Optional tenant ID.
 * @param fetchFn Optional fetch implementation.
 */
export async function signInWithIdp(
    providerIdToken: string | ProviderCredential,
    requestUri: string,
    providerId = 'google.com',
    key: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    return executeProviderSignIn(
        { credential: providerIdToken, providerId, requestUri },
        key,
        tenantId,
        fetchFn
    );
}

type ProviderSignInRequest = { idToken?: string } & (
    | {
          credential: string | ProviderCredential;
          providerId: string;
          requestUri: string;
          callback?: never;
      }
    | { callback: ProviderCallback; credential?: never }
);

/** Shared credential, callback, and linking transport. @internal */
export async function executeProviderSignIn(
    request: ProviderSignInRequest,
    key: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
): Promise<{
    data: FirebaseIdpSignInResponse | null;
    error: FirebaseEdgeError | null;
}> {
    const { callback, idToken } = request;
    if (
        callback &&
        (!callback.requestUri ||
            (!callback.sessionId && !callback.pendingToken))
    )
        throw new FirebaseEdgeError({
            code: 'auth/invalid-credential',
            message:
                'Callback URL and session ID or pending token are required.'
        });
    const body = {
        ...(callback
            ? {
                  requestUri: callback.requestUri,
                  ...(callback.pendingToken
                      ? { pendingToken: callback.pendingToken }
                      : {
                            postBody: callback.postBody,
                            sessionId: callback.sessionId
                        })
              }
            : {
                  postBody: providerCredentialBody(
                      request.credential,
                      request.providerId
                  ),
                  requestUri: request.requestUri
              }),
        ...(idToken && { idToken }),
        returnSecureToken: true as const,
        returnIdpCredential: true as const,
        ...(tenantId && { tenantId })
    };
    const { data, error } = await restFetch<
        FirebaseIdpSignInResponse,
        FirebaseRestError
    >(createIdentityURL('signInWithIdp'), {
        global: { fetch: fetchFn },
        body,
        params: { key }
    });
    if (error) return { data: null, error: mapFirebaseError(error.error) };
    if (data?.errorMessage) {
        // Retain the returned credential for the server's opt-in auto-link flow.
        if (data.errorMessage === 'EMAIL_EXISTS' && !idToken)
            return { data: { ...data, needConfirmation: true }, error: null };
        return {
            data: null,
            error: mapFirebaseError({ code: 400, message: data.errorMessage })
        };
    }
    return { data, error: null };
}

/**
 * Signs a user in with a Firebase custom token.
 *
 * @param jwtToken Firebase custom token (JWT).
 * @param key Firebase Web API key.
 * @param tenantId Optional tenant ID.
 * @param fetchFn Optional fetch implementation.
 */
export async function signInWithCustomToken(
    jwtToken: string,
    key: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createIdentityURL('signInWithCustomToken');

    const body = {
        token: jwtToken,
        returnSecureToken: true as const,
        ...(tenantId && { tenantId })
    };

    const { data, error } = await restFetch<
        FirebaseIdpSignInResponse,
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body,
        params: {
            key
        }
    });

    return {
        data,
        error: error ? mapFirebaseError(error.error) : null
    };
}

/**
 * Looks up a user record by UID, email, or phone number.
 *
 * @param identifier Lookup key (uid/email/phoneNumber).
 * @param token Google OAuth access token with Identity Toolkit scope.
 * @param project_id Firebase project ID.
 * @param tenantId Optional tenant ID.
 * @param fetchFn Optional fetch implementation.
 */
export async function getAccountInfo(
    identifier: { uid: string } | { email: string } | { phoneNumber: string },
    token: string,
    project_id: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createAdminIdentityURL(project_id, 'lookup', true, tenantId);

    const body: Record<string, any> = {
        ...('uid' in identifier && { localId: [identifier.uid] }),
        ...('email' in identifier && { email: [identifier.email] }),
        ...('phoneNumber' in identifier && {
            phoneNumber: [identifier.phoneNumber]
        }),
        ...(tenantId && { tenantId })
    };

    const { data, error } = await restFetch<
        { users: UserInfo[] },
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body,
        bearerToken: token
    });

    const userData = data?.users?.length ? data.users[0] : null;

    return {
        data: userData,
        error: error ? mapFirebaseError(error.error) : null
    };
}

/**
 * Downloads one page of user accounts for FirebaseAdminAuth.listUsers.
 * @param token Google OAuth access token.
 * @param project_id Firebase project ID.
 * @param maxResults Page size, already validated by the admin auth method.
 * @param pageToken Optional token from the previous page.
 * @param tenantId Optional tenant ID.
 * @param fetchFn Optional fetch implementation.
 * @internal
 */
export async function downloadAccount(
    token: string,
    project_id: string,
    maxResults = 1000,
    pageToken?: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createAdminIdentityURL(project_id, 'batchGet', true, tenantId);
    const { data, error } = await restFetch<
        ListUsersResponse,
        FirebaseRestError
    >(url, {
        method: 'GET',
        bearerToken: token,
        global: { fetch: fetchFn },
        params: {
            maxResults: String(maxResults),
            ...(pageToken !== undefined && { nextPageToken: pageToken })
        }
    });

    if (error) {
        return {
            data: null,
            error: normalizeAdminEndpointError(error)
        };
    }

    return { data, error: null };
}

/**
 * Creates a Firebase session cookie from an ID token.
 *
 * @param idToken Firebase ID token.
 * @param token Google OAuth access token with Identity Toolkit scope.
 * @param project_id Firebase project ID.
 * @param expiresIn_ms Session cookie TTL in milliseconds.
 * @param tenantId Optional tenant ID.
 * @param fetchFn Optional fetch implementation.
 */
export async function createSessionCookie(
    idToken: string,
    token: string,
    project_id: string,
    expiresIn_ms: number = 60 * 60 * 24 * 14 * 1000,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createAdminIdentityURL(
        project_id,
        'createSessionCookie',
        false,
        tenantId
    );

    const body = {
        idToken,
        validDuration: Math.floor(expiresIn_ms / 1000),
        ...(tenantId && { tenantId })
    };

    const { data, error } = await restFetch<
        { sessionCookie: string },
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body,
        bearerToken: token
    });

    return {
        data: data?.sessionCookie || null,
        error: error ? mapFirebaseError(error.error) : null
    };
}

/**
 * Fetches Secure Token Service JSON Web Keys (JWKs) used to verify Firebase ID tokens.
 *
 * @param fetchFn Optional fetch implementation.
 */
export async function getJWKs(fetchFn?: typeof globalThis.fetch) {
    const url =
        'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

    const { data, error } = await restFetch<
        { keys: (JsonWebKey & { kid: string })[] },
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        method: 'GET'
    });

    return {
        data: data?.keys || null,
        error: error ? mapFirebaseError(error.error) : null
    };
}

/**
 * Fetches Firebase Auth public keys (legacy endpoint).
 *
 * @param fetchFn Optional fetch implementation.
 */
export async function getPublicKeys(fetchFn?: typeof globalThis.fetch) {
    const url =
        'https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys';

    const { data, error } = await restFetch<
        Record<string, string>,
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        method: 'GET'
    });

    return {
        data,
        error: error ? mapFirebaseError(error.error) : null
    };
}

/**
 * Sends an out-of-band email action.
 *
 * Overloads support password reset and email verification.
 */
export async function sendOobCode(
    requestType: 'PASSWORD_RESET',
    key: string,
    options: {
        email: string;
        locale?: string;
        continueUrl?: string;
    },
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
): Promise<{ data: { email: string } | null; error: FirebaseEdgeError | null }>;

export async function sendOobCode(
    requestType: 'VERIFY_EMAIL',
    key: string,
    options: {
        idToken: string;
        locale?: string;
        continueUrl?: string;
    },
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
): Promise<{ data: { email: string } | null; error: FirebaseEdgeError | null }>;

export async function sendOobCode(
    requestType: 'EMAIL_SIGNIN',
    key: string,
    options: { email: string; continueUrl: string; locale?: string },
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
): Promise<{ data: { email: string } | null; error: FirebaseEdgeError | null }>;

export async function sendOobCode(
    requestType: 'VERIFY_AND_CHANGE_EMAIL',
    key: string,
    options: {
        idToken: string;
        newEmail: string;
        continueUrl?: string;
        locale?: string;
    },
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
): Promise<{ data: { email: string } | null; error: FirebaseEdgeError | null }>;

export async function sendOobCode(
    requestType:
        | 'PASSWORD_RESET'
        | 'VERIFY_EMAIL'
        | 'EMAIL_SIGNIN'
        | 'VERIFY_AND_CHANGE_EMAIL',
    key: string,
    options: {
        email?: string;
        newEmail?: string;
        idToken?: string;
        locale?: string;
        continueUrl?: string;
    },
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    if (
        requestType === 'PASSWORD_RESET' ||
        requestType === 'VERIFY_AND_CHANGE_EMAIL'
    ) {
        const validated = buildEmailActionRequest(
            'PASSWORD_RESET',
            requestType === 'PASSWORD_RESET'
                ? (options.email ?? '')
                : (options.newEmail ?? ''),
            options.continueUrl === undefined
                ? undefined
                : { url: options.continueUrl }
        );
        if (validated.error) return { data: null, error: validated.error };
        if (
            requestType === 'VERIFY_AND_CHANGE_EMAIL' &&
            !options.idToken?.trim()
        )
            return {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-id-token',
                    message: 'A signed-in user is required.'
                })
            };
    }
    if (requestType === 'EMAIL_SIGNIN') {
        const validated = buildEmailActionRequest(
            'EMAIL_SIGNIN',
            options.email ?? '',
            {
                url: options.continueUrl ?? '',
                handleCodeInApp: true
            }
        );
        if (validated.error) return { data: null, error: validated.error };
    }
    const url = createIdentityURL('sendOobCode');

    const body: Record<string, any> = {
        requestType,
        canHandleCodeInApp: requestType === 'EMAIL_SIGNIN',
        ...(options.email && { email: options.email }),
        ...(options.newEmail && { newEmail: options.newEmail }),
        ...(options.idToken && { idToken: options.idToken }),
        ...(options.continueUrl && { continueUrl: options.continueUrl }),
        ...(tenantId && { tenantId })
    };

    const headers: Record<string, string> = {};
    if (options.locale) {
        headers['X-Firebase-Locale'] = options.locale;
    }

    const { data, error } = await restFetch<
        { email: string },
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body,
        params: {
            key
        },
        headers
    });

    return {
        data,
        error: error ? mapFirebaseError(error.error) : null
    };
}

/**
 * Completes email-link sign-in using an OOB code.
 *
 * @param oobCode Out-of-band code from the email link.
 * @param email Email address used in the sign-in flow.
 * @param key Firebase Web API key.
 * @param idToken Optional existing ID token (for linking flows).
 * @param tenantId Optional tenant ID.
 * @param fetchFn Optional fetch implementation.
 */
export async function signInWithEmailLink(
    oobCode: string,
    email: string,
    key: string,
    idToken?: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createIdentityURL('signInWithEmailLink');

    const body = {
        oobCode,
        email,
        ...(idToken && { idToken }),
        ...(tenantId && { tenantId })
    };

    const { data, error } = await restFetch<
        FirebaseIdpSignInResponse,
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body,
        params: {
            key
        }
    });

    return {
        data,
        error: error ? mapFirebaseError(error.error) : null
    };
}

/**
 * Links an OAuth credential to an existing Firebase user.
 *
 * @param idToken Current user's Firebase ID token.
 * @param providerIdToken The IdP token (GitHub access token or OIDC ID token).
 * @param requestUri The origin/URL of the linking request.
 * @param providerId Provider ID (e.g. "google.com", "github.com").
 * @param key Firebase Web API key.
 * @param tenantId Optional tenant ID.
 * @param fetchFn Optional fetch implementation.
 */
export async function linkWithOAuthCredential(
    idToken: string,
    providerIdToken: string | ProviderCredential,
    requestUri: string,
    providerId: string,
    key: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    return executeProviderSignIn(
        { credential: providerIdToken, providerId, requestUri, idToken },
        key,
        tenantId,
        fetchFn
    );
}

/**
 * Unlinks a provider from a Firebase user.
 *
 * @param idToken Current user's Firebase ID token.
 * @param providerId Provider ID to remove.
 * @param key Firebase Web API key.
 * @param tenantId Optional tenant ID.
 * @param fetchFn Optional fetch implementation.
 */
export async function unlinkProvider(
    idToken: string,
    providerId: string,
    key: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createIdentityURL('update');

    const body = {
        idToken,
        deleteProvider: [providerId],
        ...(tenantId && { tenantId })
    };

    const { data, error } = await restFetch<
        FirebaseUpdateAccountResponse,
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body,
        params: {
            key
        }
    });

    return {
        data,
        error: error ? mapFirebaseError(error.error) : null
    };
}

/**
 * Updates a user via the Identity Toolkit Admin API.
 *
 * @param projectId Firebase project ID.
 * @param localId User UID.
 * @param updates UpdateAccount request fields.
 * @param googleOAuthAccessToken Google OAuth access token with Identity Toolkit scope.
 * @param fetchFn Optional fetch implementation.
 * @param tenantId Optional tenant ID.
 */
export async function updateAccountAdmin(
    projectId: string,
    localId: string,
    updates: UpdateAccountRequest,
    googleOAuthAccessToken: string,
    fetchFn?: typeof globalThis.fetch,
    tenantId?: string
) {
    const url = createAdminIdentityURL(projectId, 'update', true, tenantId);

    const body = {
        localId,
        ...updates
    };

    const { data, error } = await restFetch<
        FirebaseUpdateAccountResponse,
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body,
        bearerToken: googleOAuthAccessToken
    });

    if (error)
        return {
            data: null,
            error: normalizeAdminEndpointError(error)
        };
    return { data, error: null };
}

/** Create an account using already validated and translated admin properties. */
export async function createAccountAdmin(
    projectId: string,
    properties: UpdateAccountRequest,
    token: string,
    fetchFn?: typeof globalThis.fetch,
    tenantId?: string
) {
    const url = createAdminIdentityURL(projectId, '', true, tenantId);
    const { data, error } = await restFetch<
        { localId: string },
        FirebaseRestError
    >(url, {
        body: properties,
        bearerToken: token,
        global: { fetch: fetchFn }
    });
    if (error)
        return {
            data: null,
            error: normalizeAdminEndpointError(error)
        };
    return { data, error: null };
}

/** Delete a single user account using admin credentials. */
export async function deleteAccountAdmin(
    projectId: string,
    uid: string,
    token: string,
    fetchFn?: typeof globalThis.fetch,
    tenantId?: string
) {
    const url = createAdminIdentityURL(projectId, 'delete', true, tenantId);
    const { error } = await restFetch<object, FirebaseRestError>(url, {
        body: { localId: uid },
        bearerToken: token,
        global: { fetch: fetchFn }
    });
    if (error)
        return {
            error: normalizeAdminEndpointError(error)
        };
    return { error: null };
}

/**
 * Revokes refresh tokens for a user by setting `validSince` to now.
 *
 * @param projectId Firebase project ID.
 * @param uid User UID.
 * @param googleOAuthAccessToken Google OAuth access token with Identity Toolkit scope.
 * @param fetchFn Optional fetch implementation.
 * @param tenantId Optional tenant ID.
 */
export async function revokeRefreshTokens(
    projectId: string,
    uid: string,
    googleOAuthAccessToken: string,
    fetchFn?: typeof globalThis.fetch,
    tenantId?: string
) {
    const nowSeconds = Math.floor(Date.now() / 1000).toString();

    return updateAccountAdmin(
        projectId,
        uid,
        { validSince: nowSeconds },
        googleOAuthAccessToken,
        fetchFn,
        tenantId
    );
}

/** Complete a password reset using the emailed code; Firebase enforces password policy. */
export async function confirmPasswordReset(
    oobCode: string,
    newPassword: string,
    key: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    if (!oobCode?.trim())
        return {
            data: null,
            error: new FirebaseEdgeError({
                code: 'auth/invalid-action-code',
                message: 'An action code is required.'
            })
        };
    if (typeof newPassword !== 'string' || !newPassword.length)
        return {
            data: null,
            error: new FirebaseEdgeError({
                code: 'auth/invalid-password',
                message: 'A new password is required.'
            })
        };
    const { data, error } = await restFetch<
        { email: string },
        FirebaseRestError
    >(createIdentityURL('resetPassword'), {
        global: { fetch: fetchFn },
        params: { key },
        body: { oobCode, newPassword, ...(tenantId && { tenantId }) }
    });
    return { data, error: error ? mapFirebaseError(error.error) : null };
}

/** Apply an emailed verification, email-change, or email-recovery code. */
export async function applyActionCode(
    oobCode: string,
    key: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    if (!oobCode?.trim())
        return {
            data: null,
            error: new FirebaseEdgeError({
                code: 'auth/invalid-action-code',
                message: 'An action code is required.'
            })
        };
    const { data, error } = await restFetch<
        { email?: string; localId?: string },
        FirebaseRestError
    >(createIdentityURL('update'), {
        global: { fetch: fetchFn },
        params: { key },
        body: { oobCode, ...(tenantId && { tenantId }) }
    });
    return { data, error: error ? mapFirebaseError(error.error) : null };
}
