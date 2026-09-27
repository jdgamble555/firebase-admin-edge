import { page } from 'vitest/browser';
import { expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import About from './+page.svelte';

it('displays the Firestore name and description as text', async () => {
	const name = 'About <strong>our app</strong>';
	const description = 'Description with <em>markup</em>\nand another line';
	const { container } = render(About, {
		data: { user: null, name, description },
		form: null,
		params: {}
	});

	await expect.element(page.getByRole('heading', { name: 'About' })).toBeVisible();
	await expect.element(page.getByText(name)).toBeVisible();
	await expect.element(page.getByText(description)).toBeVisible();
	expect(container.querySelector('strong')).toBeNull();
	expect(container.querySelector('em')).toBeNull();
});
