import { page } from 'vitest/browser';
import { expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import ChangeEmail from './+page.svelte';

it('offers a server-side email change and confirms delivery', async () => {
	const { container } = render(ChangeEmail, {
		data: { user: null },
		params: {},
		form: { message: 'Check your new email.', emailSent: true }
	});
	await expect.element(page.getByRole('button', { name: 'Send confirmation link' })).toBeVisible();
	await expect.element(page.getByRole('status')).toHaveTextContent('Check your new email.');
	expect(container.querySelector('form[action="?/changeEmail"]')?.getAttribute('method')).toBe(
		'POST'
	);
});
