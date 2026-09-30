import { safeParse } from 'valibot';
import { callbackSchema } from '$lib/form-schemas';
import { error, fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ url, locals: { fbServer } }) => {
	// Email links need confirmation; inspecting them must not consume the code.
	const { error: actionError, data: action } = fbServer.getCallbackAction(url);

	if (actionError) {
		error(400, actionError.message);
	}

	if (action) {
		return action;
	}

	// Provider callbacks can complete immediately.
	const { error: callbackError, data } = await fbServer.handleCallback(url);

	if (callbackError) {
		error(400, callbackError.message);
	}

	if (data.type === 'redirect') {
		redirect(302, data.url);
	}
};

export const actions = {
	default: async ({ url, request, locals: { fbServer } }) => {
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

		const { error: callbackError, data } = await fbServer.handleCallback(url, {
			email: email || undefined,
			newPassword: password,
			confirmPassword
		});

		if (callbackError) {
			return fail(400, {
				message: callbackError.message,
				complete: false,
				needsEmail: 'code' in callbackError && callbackError.code === 'auth/missing-email'
			});
		}

		if (data.type === 'redirect') {
			redirect(303, data.url);
		}

		return { message: data.message, complete: true, needsEmail: false };
	}
} satisfies Actions;
