import { page } from 'vitest/browser';
import { describe, expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import Dashboard from './+page.svelte';

describe('dashboard provider confirmation', () => {
	it.each([
		{ connected: true, action: '?/removeProvider', verb: 'Disconnect' },
		{ connected: false, action: '?/addProvider', verb: 'Connect' }
	])('confirms $verb before changing the provider', async ({ connected, action, verb }) => {
		const { container } = render(Dashboard, {
			data: { user: null, providers: { 'google.com': connected } },
			params: {},
			form: null
		});
		const checkbox = page.getByRole('checkbox', { name: 'google.com' });

		await checkbox.click();

		await expect.element(page.getByRole('dialog', { name: `${verb} google.com?` })).toBeVisible();
		expect(container.querySelector('input[type="checkbox"]')).toHaveProperty('checked', connected);
		expect(container.querySelector('form')?.getAttribute('action')).toBe(action);
		expect(container.querySelector('input[name="provider"]')).toHaveProperty('value', 'google.com');

		await page.getByRole('button', { name: 'Cancel' }).click();

		expect(container.querySelector('dialog')).toHaveProperty('open', false);
		expect(container.querySelector('input[type="checkbox"]')).toHaveProperty('checked', connected);
	});

	it('shows an action failure on the page', async () => {
		render(Dashboard, {
			data: { user: null, providers: { 'google.com': true } },
			params: {},
			form: { message: 'Unable to disconnect provider' }
		});

		await expect
			.element(page.getByRole('alert'))
			.toHaveTextContent('Unable to disconnect provider');
	});
});
