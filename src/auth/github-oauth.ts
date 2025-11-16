import { restFetch } from '../rest-fetch.js';

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

export function createGitHubOAuthLoginUrl(
    redirect_uri: string,
    path: string,
    client_id: string
) {
    return new URL(
        'https://github.com/login/oauth/authorize?' +
            new URLSearchParams({
                client_id,
                redirect_uri,
                scope: 'read:user user:email',
                state: JSON.stringify({
                    next: path,
                    provider: 'github'
                })
            }).toString()
    ).toString();
}

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
        form: true
    });

    return {
        data,
        error: error ? error.error : null
    };
}
