import { error, redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ url, locals: { authServer } }) => {
	const { data: next, error: loginError } = await authServer.signInWithCallback(url);

	if (loginError) {
		error(400, loginError.message);
	}

	redirect(302, next);
};
