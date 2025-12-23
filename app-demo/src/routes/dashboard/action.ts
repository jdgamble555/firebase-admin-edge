import { deserialize } from '$app/forms';
import type { ActionResult } from '@sveltejs/kit';

export const addProvider = async (provider: string) => {
	const data = new FormData();
	data.append('provider', provider);

	const response = await fetch('/dashboard?/addProvider', {
		method: 'POST',
		body: data
	});

	const result: ActionResult = deserialize(await response.text());

	return result;
};

export const removeProvider = async (provider: string) => {
	const data = new FormData();
	data.append('provider', provider);

	const response = await fetch('/dashboard?/removeProvider', {
		method: 'POST',
		body: data
	});

	const result: ActionResult = deserialize(await response.text());

	return result;
};
