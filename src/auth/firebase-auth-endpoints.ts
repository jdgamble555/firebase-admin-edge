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
import type { JsonWebKey } from 'crypto';
import { mapFirebaseError } from './auth-endpoint-errors.js';
import type { FirebaseEdgeError } from './errors.js';

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
    tenantId?: string
) {
    if (tenantId) {
        // Use Identity Platform API for tenant-specific operations
        return `https://identitytoolkit.googleapis.com/v1/projects/${project_id}/tenants/${tenantId}${accounts ? '/accounts' : ''}:${name}`;
    }
    return `https://identitytoolkit.googleapis.com/v1/projects/${project_id}${accounts ? '/accounts' : ''}:${name}`;
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
    fetchFn?: typeof globalThis.fetch
) {
    const url = createIdentityURL('createAuthUri');

    const body = {
        continueUri: redirect_uri,
        providerId: 'google.com' as const,
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
    providerIdToken: string,
    requestUri: string,
    providerId = 'google.com',
    key: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createIdentityURL('signInWithIdp');

    const tokenField =
        providerId === 'github.com' ? 'access_token' : 'id_token';

    const postBody = new URLSearchParams({
        [tokenField]: providerIdToken,
        providerId
    }).toString();

    const body = {
        postBody,
        requestUri,
        returnSecureToken: true as const,
        returnIdpCredential: true as const,
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
        ...('uid' in identifier && { localId: identifier.uid }),
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

    const userData = data?.users.length ? data.users[0] : null;

    return {
        data: userData,
        error: error ? mapFirebaseError(error.error) : null
    };
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
    requestType: 'PASSWORD_RESET' | 'VERIFY_EMAIL',
    key: string,
    options: {
        email?: string;
        idToken?: string;
        locale?: string;
        continueUrl?: string;
    },
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createIdentityURL('sendOobCode');

    const body: Record<string, any> = {
        requestType,
        canHandleCodeInApp: false,
        ...(options.email && { email: options.email }),
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
    providerIdToken: string,
    requestUri: string,
    providerId: string,
    key: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createIdentityURL('signInWithIdp');

    const tokenField =
        providerId === 'github.com' ? 'access_token' : 'id_token';

    const postBody = new URLSearchParams({
        [tokenField]: providerIdToken,
        providerId
    }).toString();

    const body = {
        idToken,
        postBody,
        requestUri,
        returnSecureToken: true as const,
        returnIdpCredential: true as const,
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

    return {
        data,
        error: error ? mapFirebaseError(error.error) : null
    };
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
