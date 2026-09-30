import { safeParse } from 'valibot';
import { emailSchema } from '$lib/form-schemas';
import { fail } from '@sveltejs/kit';
import type { Actions } from './$types';

export const actions = {
	default: async ({ request, locals: { fbServer } }) => {
		const form = await request.formData();
		const { success, output: email, issues } = safeParse(emailSchema, form.get('email'));

		if (!success) {
			return fail(400, { message: issues[0].message, sent: false });
		}

		const { error } = await fbServer.sendPasswordResetEmail(email);

		// Do not reveal whether an account exists for this email.

		if (error && !('code' in error && error.code === 'auth/endpoint-user-not-found')) {
			return fail(400, { message: error.message, sent: false });
		}

		return {
			message: 'If an account exists for this email, you’ll receive a password reset link.',
			sent: true
		};
	}
} satisfies Actions;
