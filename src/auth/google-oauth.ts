import type {
    FirebaseRestError,
    GoogleTokenResponse,
    ServiceAccount
} from './firebase-types.js';
import { restFetch } from '../rest-fetch.js';
import { signJWT } from './firebase-jwt.js';

// TODO - allow scope customization

export function createGoogleOAuthLoginUrl(
    redirect_uri: string,
    path: string,
    client_id: string
) {
    return new URL(
        'https://accounts.google.com/o/oauth2/v2/auth?' +
            new URLSearchParams({
                client_id,
                redirect_uri,
                response_type: 'code',
                scope: 'openid email profile',
                access_type: 'offline',
                prompt: 'consent',
                state: JSON.stringify({
                    next: path,
                    provider: 'google'
                })
            }).toString()
    ).toString();
}

export async function exchangeCodeForGoogleIdToken(
    code: string,
    redirect_uri: string,
    client_id: string,
    client_secret: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = 'https://oauth2.googleapis.com/token';

    const { data, error } = await restFetch<
        GoogleTokenResponse,
        FirebaseRestError
    >(url, {
        global: { fetch: fetchFn },
        body: {
            code,
            client_id,
            client_secret,
            redirect_uri,
            grant_type: 'authorization_code'
        },
        form: true
    });

    return {
        data,
        error: error ? error.error : null
    };
}

export async function getToken(
    serviceAccount: ServiceAccount,
    fetch?: typeof globalThis.fetch
) {
    const url = 'https://oauth2.googleapis.com/token';

    try {
        const { data: jwtData, error: jwtError } =
            await signJWT(serviceAccount);

        if (jwtError) {
            return {
                data: null,
                error: jwtError
            };
        }

        if (!jwtData) {
            return {
                data: null,
                error: {
                    code: 500,
                    message: 'No JWT data returned',
                    errors: []
                }
            };
        }

        const { data, error } = await restFetch<
            GoogleTokenResponse,
            FirebaseRestError
        >(url, {
            global: { fetch },
            body: {
                grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                assertion: jwtData
            },
            headers: {
                'Cache-Control': 'no-cache',
                Host: 'oauth2.googleapis.com'
            },
            form: true
        });

        return {
            data,
            error: error ? error.error : null
        };
    } catch (e: unknown) {
        if (e instanceof Error) {
            return {
                data: null,
                error: {
                    code: 500,
                    message: e.message,
                    errors: []
                }
            };
        }
    }

    return {
        data: null,
        error: {
            code: 500,
            message: 'Unknown error',
            errors: []
        }
    };
}
