import { getRequestEvent } from "$app/server";

// Config Options
const client_redirect_uri = '/auth/callback';
const DEFAULT_REDIRECT_PAGE = '/';


export const getPathname = () => {

    const { request } = getRequestEvent();

    const referer = request.headers.get('referer');

    if (!referer) {
        return DEFAULT_REDIRECT_PAGE;
    }

    const url = new URL(referer);
    
    return url.searchParams.get("next") || DEFAULT_REDIRECT_PAGE;
}

export const getRedirectUri = () => {

    const { url } = getRequestEvent();

    return url.origin + client_redirect_uri;
};