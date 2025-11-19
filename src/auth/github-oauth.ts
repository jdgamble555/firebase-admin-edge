import { restFetch } from '../rest-fetch.js';
import { FirebaseEdgeError, ensureError } from './errors.js';
import { GitHubErrorInfo } from './auth-error-codes.js';
import type { ServiceAccount } from './firebase-types.js';

export type GithubTokenResponse = {
    access_token: string;
    token_type: string;
    scope: string;
};

export type GithubOAuthError = {
    error: string;
    error_description?: string;
    error_uri?: string;
};

export async function exchangeCodeForGitHubIdToken(
    code: string,
    redirect_uri: string,
    client_id: string,
    client_secret: string,
    fetchFn?: typeof globalThis.fetch
) {
    const url = 'https://github.com/login/oauth/access_token';

    const { data, error } = await restFetch<
        GithubTokenResponse,
        GithubOAuthError
    >(url, {
        global: { fetch: fetchFn },
        body: {
            code,
            client_id,
            client_secret,
            redirect_uri
        },
        form: true,
        acceptJson: true
    });

    if (error?.error) {
        const errorCode = error.error.toLowerCase();

        if (errorCode.includes('incorrect_client_credentials')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GitHubErrorInfo.GITHUB_INCORRECT_CLIENT_CREDENTIALS,
                    {
                        context: {
                            originalError: error.error,
                            description: error.error_description
                        }
                    }
                )
            };
        }

        if (errorCode.includes('redirect_uri_mismatch')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GitHubErrorInfo.GITHUB_REDIRECT_URI_MISMATCH,
                    {
                        context: {
                            originalError: error.error,
                            description: error.error_description
                        }
                    }
                )
            };
        }

        if (errorCode.includes('bad_verification_code')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GitHubErrorInfo.GITHUB_BAD_VERIFICATION_CODE,
                    {
                        context: {
                            originalError: error.error,
                            description: error.error_description
                        }
                    }
                )
            };
        }

        if (errorCode.includes('unverified_user_email')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GitHubErrorInfo.GITHUB_UNVERIFIED_USER_EMAIL,
                    {
                        context: {
                            originalError: error.error,
                            description: error.error_description
                        }
                    }
                )
            };
        }

        if (errorCode.includes('access_denied')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GitHubErrorInfo.GITHUB_ACCESS_DENIED,
                    {
                        context: {
                            originalError: error.error,
                            description: error.error_description
                        }
                    }
                )
            };
        }

        if (errorCode.includes('unsupported_grant_type')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GitHubErrorInfo.GITHUB_UNSUPPORTED_GRANT_TYPE,
                    {
                        context: {
                            originalError: error.error,
                            description: error.error_description
                        }
                    }
                )
            };
        }

        if (errorCode.includes('invalid_client')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GitHubErrorInfo.GITHUB_INVALID_CLIENT,
                    {
                        context: {
                            originalError: error.error,
                            description: error.error_description
                        }
                    }
                )
            };
        }

        if (errorCode.includes('invalid_request')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GitHubErrorInfo.GITHUB_INVALID_REQUEST,
                    {
                        context: {
                            originalError: error.error,
                            description: error.error_description
                        }
                    }
                )
            };
        }

        if (errorCode.includes('unauthorized_client')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GitHubErrorInfo.GITHUB_UNAUTHORIZED_CLIENT,
                    {
                        context: {
                            originalError: error.error,
                            description: error.error_description
                        }
                    }
                )
            };
        }

        if (errorCode.includes('invalid_scope')) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    GitHubErrorInfo.GITHUB_INVALID_SCOPE,
                    {
                        context: {
                            originalError: error.error,
                            description: error.error_description
                        }
                    }
                )
            };
        }

        // Default case for unrecognized errors
        return {
            data: null,
            error: new FirebaseEdgeError(
                GitHubErrorInfo.GITHUB_CODE_EXCHANGE_FAILED,
                {
                    context: {
                        originalError: error.error,
                        description: error.error_description
                    }
                }
            )
        };
    }

    return {
        data,
        error: null
    };
}
