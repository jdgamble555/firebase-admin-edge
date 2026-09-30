import { safeParse } from 'valibot';
import { emailSchema } from '$lib/form-schemas';
import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';

export const load = (async ({ parent, url }) => {
	const next = url.searchParams.get('next') || '/';

	const { user } = await parent();

	if (user) {
		redirect(302, next);
	}
}) satisfies PageServerLoad;

export const actions = {
	email: async ({ locals: { fbServer }, request }) => {
		const form = await request.formData();
		const { success, output: email, issues } = safeParse(emailSchema, form.get('email'));

		if (!success) {
			return fail(400, { message: issues[0].message, sent: false });
		}

		// Carry email in the link so it also works on another device.
		const { error } = await fbServer.sendSignInLinkToEmail(email, '/dashboard', {
			includeEmailInLink: true
		});

		if (error) {
			return fail(400, { message: error.message, sent: false });
		}

		return { message: 'Check your email for your sign-in link.', sent: true };
	},

	google: async ({ locals: { fbServer }, url }) => {
		const next = url.searchParams.get('next') || '/';

		const loginUrl = await fbServer.getProviderLoginURL('google', next);

		redirect(302, loginUrl);
	},

	github: async ({ locals: { fbServer }, url }) => {
		const next = url.searchParams.get('next') || '/';

		const loginUrl = await fbServer.getProviderLoginURL('github', next);

		redirect(302, loginUrl);
	},

	logout: async ({ locals: { fbServer } }) => {
		fbServer.signOut();

		redirect(302, '/');
	}
} satisfies Actions;
