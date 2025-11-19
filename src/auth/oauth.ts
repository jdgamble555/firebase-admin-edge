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
