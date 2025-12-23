import { redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { getPathname } from '$lib/svelte-helpers';

export const load = (async ({ parent, url }) => {
	const next = url.searchParams.get('next') || '/';

	const { user } = await parent();

	if (user) {
		redirect(302, next);
	}
}) satisfies PageServerLoad;

export const actions = {
	google: async ({ locals: { authServer } }) => {
		const next = getPathname();

		const loginUrl = await authServer.getGoogleLoginURL(next);

		redirect(302, loginUrl);
	},

	github: async ({ locals: { authServer } }) => {
		const next = getPathname();

		const loginUrl = await authServer.getGitHubLoginURL(next);

		redirect(302, loginUrl);
	},

	logout: async ({ locals: { authServer } }) => {
		authServer.signOut();

		redirect(302, '/');
	}
} satisfies Actions;
