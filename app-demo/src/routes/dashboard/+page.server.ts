import { redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { fail } from 'assert/strict';

export const load = (async ({ parent, url }) => {
	const next = url.searchParams.get('next') || '/';

	const { user } = await parent();

	if (!user) {
		redirect(302, next);
	}

	const identities = user.firebase.identities;

	const providers: Record<string, boolean> = {
		'google.com': !!identities['google.com'],
		'github.com': !!identities['github.com'],
		email: !!identities['email']
	};

	return {
		providers
	};
}) satisfies PageServerLoad;

export const actions = {
	addProvider: async ({ locals: { authServer }, request, url }) => {
		const form = await request.formData();
		const provider = String(form.get('provider') ?? '');
		const next = url.pathname;

		if (provider === 'google.com') {
			const linkUrl = await authServer.getGoogleLinkURL(next);
			redirect(302, linkUrl);
		}

		if (provider === 'github.com') {
			const linkUrl = await authServer.getGitHubLinkURL(next);
			redirect(302, linkUrl);
		}

		return fail('Unsupported provider');
	},

	removeProvider: async ({ locals: { authServer }, request }) => {
		const form = await request.formData();
		const provider = String(form.get('provider') ?? '');

		if (!provider) {
			return fail('No provider specified');
		}

		const { error } = await authServer.unlinkProvider(provider);
		if (error) {
			return fail(error.message);
		}

		return { success: true };
	}
} satisfies Actions;
