import type {
    FirebaseRestError,
    GoogleTokenResponse,
    ServiceAccount
} from './firebase-types.js';
import { restFetch } from '../rest-fetch.js';
import { signJWT } from './firebase-jwt.js';
import { FirebaseEdgeError, ensureError } from './errors.js';
import { GoogleErrorInfo } from './auth-error-codes.js';

type GoogleOAuthError = {
    error: string;
    error_description?: string;
};

/** Read both OAuth and Firebase-style token endpoint failures. @internal */
function googleErrorMessage(
    error: GoogleOAuthError | FirebaseRestError | string | null
): string | undefined {
    if (!error) return undefined;
    if (typeof error === 'string') return error;
    if (typeof error.error !== 'string') return error.error?.message;
    const description =
        'error_description' in error ? error.error_description : undefined;
    return [error.error, description].filter(Boolean).join(': ');
}

export type TokenResults =
    | {
          data: null;
          error: FirebaseEdgeError;
      }
    | {
          data: GoogleTokenResponse;
          error: null;
      };

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
            GoogleOAuthError | FirebaseRestError | string
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

        const originalError = googleErrorMessage(error);
        if (originalError) {
            const errorMessage = originalError.toLowerCase();

            if (
                errorMessage.includes('unavailable') ||
                errorMessage.includes('503')
            ) {
                return {
                    data: null,
                    error: new FirebaseEdgeError(
                        GoogleErrorInfo.GOOGLE_TEMPORARILY_UNAVAILABLE,
                        {
                            context: { originalError }
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
                            context: { originalError }
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
                        context: { originalError }
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
