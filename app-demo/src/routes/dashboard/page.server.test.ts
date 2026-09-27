import { describe, expect, it, vi } from 'vitest';
import { actions, load } from './+page.server';

describe('dashboard', () => {
	it('redirects visitors without a session', async () => {
		const event = {
			url: new URL('http://localhost:5173/dashboard'),
			parent: vi.fn().mockResolvedValue({ user: null })
		};

		const result = load(event as unknown as Parameters<typeof load>[0]);

		await expect(result).rejects.toMatchObject({ status: 302, location: '/' });
	});

	it.each(['google.com', 'github.com'])('starts linking %s', async (provider) => {
		const authServer = {
			getProviderLinkURL: vi.fn().mockResolvedValue('https://provider/login')
		};
		const event = {
			url: new URL('http://localhost:5173/dashboard'),
			locals: { authServer },
			request: new Request('http://localhost:5173/dashboard?/addProvider', {
				method: 'POST',
				body: new URLSearchParams({ provider })
			})
		};

		const result = actions.addProvider(
			event as unknown as Parameters<typeof actions.addProvider>[0]
		);

		await expect(result).rejects.toMatchObject({ status: 302, location: 'https://provider/login' });
		expect(authServer.getProviderLinkURL).toHaveBeenCalledWith(
			provider === 'google.com' ? 'google' : 'github',
			'/dashboard'
		);
	});

	it('returns a form failure for unsupported providers', async () => {
		const event = {
			url: new URL('http://localhost:5173/dashboard'),
			locals: { authServer: {} },
			request: new Request('http://localhost:5173/dashboard?/addProvider', {
				method: 'POST',
				body: new URLSearchParams({ provider: 'unsupported' })
			})
		};

		const result = await actions.addProvider(
			event as unknown as Parameters<typeof actions.addProvider>[0]
		);

		expect(result).toMatchObject({ status: 400, data: { message: 'Unsupported provider' } });
	});

	it.each([
		{ provider: '', error: null, message: 'No provider specified' },
		{ provider: 'github.com', error: new Error('Unlink failed'), message: 'Unlink failed' },
		{ provider: 'github.com', error: null, message: null }
	])('handles unlinking: $message', async ({ provider, error, message }) => {
		const unlinkProvider = vi.fn().mockResolvedValue({ error });
		const event = {
			locals: { authServer: { unlinkProvider } },
			request: new Request('http://localhost:5173/dashboard?/removeProvider', {
				method: 'POST',
				body: new URLSearchParams({ provider })
			})
		};

		const result = await actions.removeProvider(
			event as unknown as Parameters<typeof actions.removeProvider>[0]
		);

		expect(result).toMatchObject(message ? { status: 400, data: { message } } : { success: true });
		if (!provider) {
			expect(unlinkProvider).not.toHaveBeenCalled();
			return;
		}
		expect(unlinkProvider).toHaveBeenCalledWith(provider);
	});
});

it.each([false, true])('requests a verified email change (failure=%s)', async (failure) => {
	const verifyBeforeUpdateEmail = vi
		.fn()
		.mockResolvedValue({ error: failure ? { message: 'Sign in again' } : null });
	const event = {
		locals: { authServer: { verifyBeforeUpdateEmail } },
		request: new Request('https://app/dashboard', {
			method: 'POST',
			body: new URLSearchParams({ email: ' new@example.com ' })
		})
	};
	const result = await actions.changeEmail(
		event as unknown as Parameters<typeof actions.changeEmail>[0]
	);
	expect(verifyBeforeUpdateEmail).toHaveBeenCalledWith('new@example.com');
	expect(result).toMatchObject(
		failure ? { status: 400, data: { emailSent: false } } : { emailSent: true }
	);
});

it.each(['', 'invalid', ' '])(
	'rejects invalid email before contacting Firebase: %s',
	async (email) => {
		const verifyBeforeUpdateEmail = vi.fn();
		const event = {
			locals: { authServer: { verifyBeforeUpdateEmail } },
			request: new Request('https://app/dashboard', {
				method: 'POST',
				body: new URLSearchParams({ email })
			})
		};
		const { status } = (await actions.changeEmail(
			event as unknown as Parameters<typeof actions.changeEmail>[0]
		)) as { status: number };
		expect(status).toBe(400);
		expect(verifyBeforeUpdateEmail).not.toHaveBeenCalled();
	}
);
