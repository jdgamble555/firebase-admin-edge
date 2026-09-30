import { safeParse } from 'valibot';
import { emailSchema } from '$lib/form-schemas';
import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';

export const load = (async ({ parent }) => {
	const { user } = await parent();

	if (!user) {
		redirect(302, '/');
	}

	return {};
}) satisfies PageServerLoad;

export const actions = {
	changeEmail: async ({ request, locals: { fbServer } }) => {
		const { data: user } = await fbServer.getUser();

		if (!user) {
			redirect(302, '/');
		}

		const form = await request.formData();
		const { success, output: email, issues } = safeParse(emailSchema, form.get('email'));

		if (!success) {
			return fail(400, { message: issues[0].message, emailSent: false });
		}

		// Firebase verifies the new address before changing the account.
		const { error } = await fbServer.verifyBeforeUpdateEmail(email);

		if (error) {
			return fail(400, { message: error.message, emailSent: false });
		}

		return { message: 'Check your new email address to confirm the change.', emailSent: true };
	}
} satisfies Actions;
