import { safeParse } from 'valibot';
import { emailSchema, linkProviderSchema, unlinkProviderSchema } from '$lib/form-schemas';
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
	changeEmail: async ({ request, locals: { authServer } }) => {
		const form = await request.formData();
		const { success, output: email, issues } = safeParse(emailSchema, form.get('email'));

		if (!success) {
			return fail(400, { message: issues[0].message, emailSent: false });
		}

		// Firebase verifies the new address before changing the account.
		const { error } = await authServer.verifyBeforeUpdateEmail(email);

		if (error) {
			return fail(400, { message: error.message, emailSent: false });
		}

		return { message: 'Check your new email address to confirm the change.', emailSent: true };
	},

	addProvider: async ({ locals: { authServer }, request, url }) => {
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
		const linkUrl = await authServer.getProviderLinkURL(
			provider === 'google.com' ? 'google' : 'github',
			url.pathname
		);

		redirect(302, linkUrl);
	},

	removeProvider: async ({ locals: { authServer }, request }) => {
		const form = await request.formData();
		const {
			success,
			output: provider,
			issues
		} = safeParse(unlinkProviderSchema, form.get('provider'));

		if (!success) {
			return fail(400, { message: issues[0].message });
		}

		const { error } = await authServer.unlinkProvider(provider);

		if (error) {
			return fail(400, { message: error.message });
		}

		return { success: true };
	}
} satisfies Actions;
