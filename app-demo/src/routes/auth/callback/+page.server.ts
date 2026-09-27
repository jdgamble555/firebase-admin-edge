import { safeParse } from 'valibot';
import { callbackSchema } from '$lib/form-schemas';
import { error as httpError, fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ url, locals: { authServer } }) => {
	// Email links need confirmation; inspecting them must not consume the code.
	const { error: actionError, data: action } = authServer.getCallbackAction(url);

	if (actionError) {
		httpError(400, actionError.message);
	}

	if (action) {
		return action;
	}

	// Provider callbacks can complete immediately.
	const { error, data } = await authServer.handleCallback(url);

	if (error) {
		httpError(400, error.message);
	}

	if (data.type === 'redirect') {
		redirect(302, data.url);
	}
};

export const actions = {
	default: async ({ url, request, locals: { authServer } }) => {
		const form = await request.formData();
		const { success, output, issues } = safeParse(callbackSchema, Object.fromEntries(form));

		if (!success) {
			return fail(400, {
				message: issues[0].message,
				complete: false,
				needsEmail: issues[0].path?.[0]?.key === 'email'
			});
		}

		// Core selects and completes the action for this link.
		const { email, password, confirmPassword } = output;

		const { error, data } = await authServer.handleCallback(url, {
			email: email || undefined,
			newPassword: password,
			confirmPassword
		});

		if (error) {
			return fail(400, {
				message: error.message,
				complete: false,
				needsEmail: 'code' in error && error.code === 'auth/missing-email'
			});
		}

		if (data.type === 'redirect') {
			redirect(303, data.url);
		}

		return { message: data.message, complete: true, needsEmail: false };
	}
} satisfies Actions;
