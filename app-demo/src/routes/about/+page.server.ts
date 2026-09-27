import { error } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { aboutConverter } from './about-converter';

export const load = (async ({ locals: { authServer } }) => {
	const { error: readError, data: document } = await authServer.firestore
		.doc('about/ZlNJrKd6LcATycPRmBPA')
		.withConverter(aboutConverter)
		.get();
	if (readError) {
		throw readError;
	}

	const about = document.data();

	if (!about) {
		error(404, 'About document not found.');
	}

	return about;
}) satisfies PageServerLoad;
