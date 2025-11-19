import type {
    FirebaseCreateAuthUriResponse,
    FirebaseIdpSignInResponse,
    FirebaseRefreshTokenResponse,
    FirebaseRestError,
    UserRecord
} from './firebase-types.js';
import { restFetch } from '../rest-fetch.js';
import type { JsonWebKey } from 'crypto';
import { mapFirebaseError } from './auth-endpoint-errors.js';

// Functions

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

function createIdentityURL(name: string) {
    // Standard Firebase Auth REST API - tenant ID goes in request body, not URL
    return `https://identitytoolkit.googleapis.com/v1/accounts:${name}`;
}

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

export async function getAccountInfoByUid(
    uid: string,
    token: string,
    project_id: string,
    tenantId?: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = createAdminIdentityURL(project_id, 'lookup', true, tenantId);

    const body = {
        localId: uid,
        ...(tenantId && { tenantId })
    };

    const { data, error } = await restFetch<
        { users: UserRecord[] },
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body,
        bearerToken: token
    });

    return {
        data: data?.users.length ? data.users[0] : null,
        error: error ? mapFirebaseError(error.error) : null
    };
}

export async function createSessionCookie(
    idToken: string,
    token: string,
    project_id: string,
    expiresIn: number = 60 * 60 * 24 * 14 * 1000,
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
        validDuration: Math.floor(expiresIn / 1000),
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
