import { error } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

export const load = (async ({ locals: { fbServer } }) => {
	const { data, error: firebaseError } = await fbServer.getUser();

	if (firebaseError) {
		error(400, firebaseError.message);
	}

	return {
		user: data
	};
}) satisfies LayoutServerLoad;
