import { page } from 'vitest/browser';
import { expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import Login from './+page.svelte';

it('offers email-link login and shows the delivery confirmation', async () => {
	const { container } = render(Login, {
		data: { user: null },
		form: { message: 'Check your email', sent: true },
		params: {}
	});
	await expect.element(page.getByRole('button', { name: 'Email me a sign-in link' })).toBeVisible();
	await expect.element(page.getByRole('status')).toHaveTextContent('Check your email');
	expect(container.querySelector('form[action="?/email"]')?.getAttribute('method')).toBe('POST');
});
