import { redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { getPathname, getRedirectUri } from '$lib/svelte-helpers';


export const load = (async ({ locals: { authServer }, url }) => {

    const next = url.searchParams.get('next') || '/';

    const { data: user } = await authServer.getUser();

    if (user) {
        redirect(302, next);
    }

}) satisfies PageServerLoad;


export const actions = {

    google: async ({ locals: { authServer } }) => {

        const redirect_uri = getRedirectUri();
        const path = getPathname();

        const loginUrl = await authServer.getGoogleLoginURL(
            redirect_uri,
            path
        );

        redirect(302, loginUrl);
    },

    github: async ({ locals: { authServer } }) => {

        const redirect_uri = getRedirectUri();
        const path = getPathname();

        const loginUrl = await authServer.getGitHubLoginURL(
            redirect_uri,
            path
        );
        
        redirect(302, loginUrl);
    },

    logout: async ({ locals: { authServer } }) => {

        authServer.signOut();

        redirect(302, '/');
    }

} satisfies Actions;