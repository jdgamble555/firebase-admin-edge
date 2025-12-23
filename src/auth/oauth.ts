export function createGitHubOAuthLoginUrl(
    redirect_uri: string,
    path: string,
    client_id: string,
    intent: 'signin' | 'link' = 'signin',
    customParameters?: Record<string, string>,
    addScopes?: string[]
) {
    const baseScopes = ['read:user', 'user:email'];
    const scopes = addScopes ? [...baseScopes, ...addScopes] : baseScopes;

    const params: Record<string, string> = {
        client_id,
        redirect_uri,
        scope: scopes.join(' '),
        state: JSON.stringify({
            intent,
            next: path,
            provider: 'github'
        })
    };

    if (customParameters) {
        Object.assign(params, customParameters);
    }

    return (
        'https://github.com/login/oauth/authorize?' +
        new URLSearchParams(params).toString()
    );
}

export function createGoogleOAuthLoginUrl(
    redirect_uri: string,
    path: string,
    client_id: string,
    intent: 'signin' | 'link' = 'signin',
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
            intent,
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

    return (
        'https://accounts.google.com/o/oauth2/v2/auth?' +
        new URLSearchParams(params).toString()
    );
}
