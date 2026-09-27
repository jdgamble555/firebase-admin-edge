import { describe, expect, it, vi } from 'vitest';
import { actions } from './+page.server';

vi.mock('$lib/svelte-helpers', () => ({ getPathname: () => '/dashboard' }));

it.each([false, true])('sends magic links with email in the flow (failure=%s)', async (failure) => {
	const sendSignInLinkToEmail = vi
		.fn()
		.mockResolvedValue(
			failure ? { error: new Error('Cannot send') } : { data: { sent: true }, error: null }
		);
	const event = {
		url: new URL('https://app/login'),
		locals: { authServer: { sendSignInLinkToEmail } },
		request: new Request('https://app/login?/email', {
			method: 'POST',
			body: new URLSearchParams({ email: ' user@example.com ' })
		})
	};
	const result = await actions.email(event as unknown as Parameters<typeof actions.email>[0]);
	expect(sendSignInLinkToEmail).toHaveBeenCalledWith('user@example.com', '/dashboard', {
		includeEmailInLink: true
	});
	expect(result).toMatchObject(failure ? { status: 400, data: { sent: false } } : { sent: true });
});

describe.each(['google', 'github'] as const)('%s login', (provider) => {
	it('redirects to Firebase-managed authorization without local provider credentials', async () => {
		const getProviderLoginURL = vi.fn().mockResolvedValue('https://accounts.google.com/authorize');
		const event = { locals: { authServer: { getProviderLoginURL } } };
		const result = actions[provider](
			event as unknown as Parameters<(typeof actions)[typeof provider]>[0]
		);
		await expect(result).rejects.toMatchObject({
			status: 302,
			location: 'https://accounts.google.com/authorize'
		});
		expect(getProviderLoginURL).toHaveBeenCalledWith(provider, '/dashboard');
	});

	it('propagates authorization failures without redirecting', async () => {
		const getProviderLoginURL = vi.fn().mockRejectedValue(new Error('Google provider disabled'));
		const event = { locals: { authServer: { getProviderLoginURL } } };
		const result = actions[provider](
			event as unknown as Parameters<(typeof actions)[typeof provider]>[0]
		);
		await expect(result).rejects.toThrow('Google provider disabled');
	});
});

it.each(['', 'invalid', ' '])(
	'rejects invalid email before contacting Firebase: %s',
	async (email) => {
		const sendSignInLinkToEmail = vi.fn();
		const event = {
			locals: { authServer: { sendSignInLinkToEmail } },
			request: new Request('https://app/login', {
				method: 'POST',
				body: new URLSearchParams({ email })
			})
		};
		const { status } = (await actions.email(
			event as unknown as Parameters<typeof actions.email>[0]
		)) as { status: number };
		expect(status).toBe(400);
		expect(sendSignInLinkToEmail).not.toHaveBeenCalled();
	}
);
