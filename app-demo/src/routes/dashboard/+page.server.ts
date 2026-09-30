import { safeParse } from 'valibot';
import { linkProviderSchema, unlinkProviderSchema } from '$lib/form-schemas';
import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';

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
	addProvider: async ({ locals: { fbServer }, request, url }) => {
		const form = await request.formData();
		const {
			success,
			output: provider,
			issues
		} = safeParse(linkProviderSchema, form.get('provider'));

		if (!success) {
			return fail(400, { message: issues[0].message });
		}

		// Return to this page after the provider confirms the link.
		const linkUrl = await fbServer.getProviderLinkURL(
			provider === 'google.com' ? 'google' : 'github',
			url.pathname
		);

		redirect(302, linkUrl);
	},

	removeProvider: async ({ locals: { fbServer }, request }) => {
		const form = await request.formData();
		const {
			success,
			output: provider,
			issues
		} = safeParse(unlinkProviderSchema, form.get('provider'));

		if (!success) {
			return fail(400, { message: issues[0].message });
		}

		const { error } = await fbServer.unlinkProvider(provider);

		if (error) {
			return fail(400, { message: error.message });
		}

		return { success: true };
	}
} satisfies Actions;
