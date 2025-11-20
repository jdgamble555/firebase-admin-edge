export function createGitHubOAuthLoginUrl(
    redirect_uri: string,
    path: string,
    client_id: string,
    customParameters?: Record<string, string>,
    addScopes?: string[]
) {
    // Build scope string with default scopes and additional ones
    const baseScopes = ['read:user', 'user:email'];
    const scopes = addScopes ? [...baseScopes, ...addScopes] : baseScopes;

    const params: Record<string, string> = {
        client_id,
        redirect_uri,
        scope: scopes.join(' '),
        state: JSON.stringify({
            next: path,
            provider: 'github'
        })
    };

    // Add custom parameters if provided (e.g., 'login', 'allow_signup')
    if (customParameters) {
        Object.assign(params, customParameters);
    }

    return new URL(
        'https://github.com/login/oauth/authorize?' +
            new URLSearchParams(params).toString()
    ).toString();
}

export function createGoogleOAuthLoginUrl(
    redirect_uri: string,
    path: string,
    client_id: string,
    languageCode?: string,
    customParameters?: Record<string, string>,
    addScopes?: string[]
) {
    // Build scope string with default scopes and additional ones
    const baseScopes = ['openid', 'email', 'profile'];
    const scopes = addScopes ? [...baseScopes, ...addScopes] : baseScopes;

    const params: Record<string, string> = {
        client_id,
        redirect_uri,
        response_type: 'code',
        scope: scopes.join(' '),
        access_type: 'offline',
        prompt: 'consent',
        state: JSON.stringify({
            next: path,
            provider: 'google'
        })
    };

    // Add language code if provided (hl parameter for Google OAuth)
    if (languageCode) {
        params.hl = languageCode;
    }

    // Add custom parameters if provided (e.g., 'login_hint', 'hd' for hosted domain)
    if (customParameters) {
        Object.assign(params, customParameters);
    }

    return new URL(
        'https://accounts.google.com/o/oauth2/v2/auth?' +
            new URLSearchParams(params).toString()
    ).toString();
}
