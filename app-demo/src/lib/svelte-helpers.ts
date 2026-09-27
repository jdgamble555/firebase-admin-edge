import { getRequestEvent } from '$app/server';

const DEFAULT_REDIRECT_PAGE = '/';

export const getPathname = () => {
	const { request } = getRequestEvent();

	const referer = request.headers.get('referer');

	if (!referer) {
		return DEFAULT_REDIRECT_PAGE;
	}

	const url = new URL(referer);

	return url.searchParams.get('next') || DEFAULT_REDIRECT_PAGE;
};
