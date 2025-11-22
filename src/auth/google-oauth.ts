import type {
    FirebaseRestError,
    GoogleTokenResponse,
    ServiceAccount
} from './firebase-types.js';
import { restFetch } from '../rest-fetch.js';
import { signJWT } from './firebase-jwt.js';
import { FirebaseEdgeError, ensureError } from './errors.js';
import { GoogleErrorInfo } from './auth-error-codes.js';

export type TokenResults =
    | {
          data: null;
          error: FirebaseEdgeError;
      }
    | {
          data: GoogleTokenResponse;
          error: null;
      };

export async function exchangeCodeForGoogleIdToken(
    code: string,
    redirect_uri: string,
    client_id: string,
    client_secret: string,
    fetchFn?: typeof globalThis.fetch
): Promise<TokenResults> {
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

    if (error?.error.message) {
        const errorMessage = error.error.message.toLowerCase();

        if (errorMessage.includes('invalid_grant')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GoogleErrorInfo.GOOGLE_INVALID_GRANT,
                    {
                        context: { originalError: error.error.message }
                    }
                )
            };
        }

        if (errorMessage.includes('invalid_client')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GoogleErrorInfo.GOOGLE_INVALID_CLIENT,
                    {
                        context: { originalError: error.error.message }
                    }
                )
            };
        }

        if (errorMessage.includes('invalid_request')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GoogleErrorInfo.GOOGLE_INVALID_REQUEST,
                    {
                        context: { originalError: error.error.message }
                    }
                )
            };
        }

        if (errorMessage.includes('access_denied')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GoogleErrorInfo.GOOGLE_ACCESS_DENIED,
                    {
                        context: { originalError: error.error.message }
                    }
                )
            };
        }

        if (errorMessage.includes('unsupported_response_type')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GoogleErrorInfo.GOOGLE_UNSUPPORTED_RESPONSE_TYPE,
                    {
                        context: { originalError: error.error.message }
                    }
                )
            };
        }

        if (errorMessage.includes('invalid_scope')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GoogleErrorInfo.GOOGLE_INVALID_SCOPE,
                    {
                        context: { originalError: error.error.message }
                    }
                )
            };
        }

        // Default case for unrecognized errors
        return {
            data: null,
            error: new FirebaseEdgeError(
                GoogleErrorInfo.GOOGLE_CODE_EXCHANGE_FAILED,
                {
                    context: { originalError: error.error.message }
                }
            )
        };
    }

    if (!data) {
        return {
            data: null,
            error: new FirebaseEdgeError(
                GoogleErrorInfo.GOOGLE_TOKEN_REQUEST_FAILED
            )
        };
    }

    return {
        data,
        error: null
    };
}

export async function getToken(
    serviceAccount: ServiceAccount,
    fetch?: typeof globalThis.fetch
): Promise<TokenResults> {
    const url = 'https://oauth2.googleapis.com/token';

    try {
        const { data: jwtData, error: jwtError } =
            await signJWT(serviceAccount);

        if (jwtError) {
            return {
                data: null,
                error: new FirebaseEdgeError(GoogleErrorInfo.JWT_SIGN_FAILED, {
                    cause: ensureError(jwtError),
                    context: { originalError: jwtError.message }
                })
            };
        }

        if (!jwtData) {
            return {
                data: null,
                error: new FirebaseEdgeError(GoogleErrorInfo.JWT_DATA_MISSING)
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

        if (error?.error.message) {
            const errorMessage = error.error.message.toLowerCase();

            if (
                errorMessage.includes('unavailable') ||
                errorMessage.includes('503')
            ) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        GoogleErrorInfo.GOOGLE_TEMPORARILY_UNAVAILABLE,
                        {
                            context: { originalError: error.error.message }
                        }
                    )
                };
            }

            if (
                errorMessage.includes('server') ||
                errorMessage.includes('500')
            ) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        GoogleErrorInfo.GOOGLE_SERVER_ERROR,
                        {
                            context: { originalError: error.error.message }
                        }
                    )
                };
            }

            // Default case for other service account token errors
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GoogleErrorInfo.SERVICE_ACCOUNT_TOKEN_FAILED,
                    {
                        context: { originalError: error.error.message }
                    }
                )
            };
        }

        if (!data) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GoogleErrorInfo.GOOGLE_TOKEN_REQUEST_FAILED
                )
            };
        }

        return {
            data,
            error: null
        };
    } catch (e) {
        return {
            data: null,
            error: new FirebaseEdgeError(
                GoogleErrorInfo.GOOGLE_TOKEN_REQUEST_FAILED,
                {
                    cause: ensureError(e),
                    context: {
                        originalError:
                            e instanceof Error ? e.message : String(e)
                    }
                }
            )
        };
    }
}
