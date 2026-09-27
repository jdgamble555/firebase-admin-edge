import { page } from 'vitest/browser';
import { expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import ResetPassword from './+page.svelte';

it('offers a server form and shows delivery status', async () => {
	const { container } = render(ResetPassword, {
		data: { user: null },
		form: { message: 'Check your email.', sent: true },
		params: {}
	});
	await expect.element(page.getByRole('button', { name: 'Send reset link' })).toBeVisible();
	await expect.element(page.getByRole('status')).toHaveTextContent('Check your email.');
	expect(container.querySelector('form')?.method).toBe('post');
});
