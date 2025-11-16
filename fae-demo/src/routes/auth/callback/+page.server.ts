import { error, redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getRedirectUri } from '$lib/svelte-helpers';


export const load: PageServerLoad = async ({ url, locals: { authServer } }) => {

    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');

    const next = state ? JSON.parse(state).next : '/';

    if (!code) {
        error(400, 'Invalid URL!');
    }

    const redirect_uri = getRedirectUri();

    const {
        error: loginError
    } = await authServer.signInWithCode(
        code,
        redirect_uri,
        state
    );

    if (loginError) {

        error(400, loginError);
    }

    redirect(302, next);
};