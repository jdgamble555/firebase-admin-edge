import { expect, it, vi } from 'vitest';
import { load, actions } from './+page.server';

it('renders core-provided action data without consuming the code', async () => {
	const data = { hasLink: true, actionMode: 'resetPassword' };
	const authServer = {
		getCallbackAction: vi.fn().mockReturnValue({ data, error: null }),
		handleCallback: vi.fn()
	};
	const url = new URL('https://app/auth/callback?link=wrapped');
	const result = await load({ url, locals: { authServer } } as unknown as Parameters<
		typeof load
	>[0]);
	expect(result).toBe(data);
	expect(authServer.getCallbackAction).toHaveBeenCalledWith(url);
	expect(authServer.handleCallback).not.toHaveBeenCalled();
});
it('redirects provider sign-ins through the shared handler', async () => {
	const authServer = {
		getCallbackAction: vi.fn().mockReturnValue({ data: null, error: null }),
		handleCallback: vi
			.fn()
			.mockResolvedValue({ data: { type: 'redirect', url: '/dashboard' }, error: null })
	};
	const url = new URL('https://app/auth/callback?code=oauth');
	const result = load({ url, locals: { authServer } } as unknown as Parameters<typeof load>[0]);
	await expect(result).rejects.toMatchObject({ status: 302, location: '/dashboard' });
	expect(authServer.handleCallback).toHaveBeenCalledWith(url);
});
it.each(['inspection', 'completion'])('shows GET errors from core %s', async (stage) => {
	const error = { message: 'Invalid callback' };
	const authServer = {
		getCallbackAction: vi
			.fn()
			.mockReturnValue({ data: null, error: stage === 'inspection' ? error : null }),
		handleCallback: vi.fn().mockResolvedValue({ data: null, error })
	};
	const result = load({
		url: new URL('https://app/callback'),
		locals: { authServer }
	} as unknown as Parameters<typeof load>[0]);
	await expect(result).rejects.toMatchObject({
		status: 400,
		body: { message: 'Invalid callback' }
	});
	if (stage === 'inspection') expect(authServer.handleCallback).not.toHaveBeenCalled();
});
it.each(['redirect', 'complete', 'auth/missing-email', 'auth/expired-action-code'])(
	'presents the core POST result: %s',
	async (kind) => {
		const error = kind.startsWith('auth/') ? { code: kind, message: 'Cannot complete' } : null;
		const handleCallback = vi.fn().mockResolvedValue({
			data: error ? null : { type: kind, url: '/dashboard', message: 'Done' },
			error
		});
		const url = new URL('https://app/auth/callback?link=wrapped');
		const event = {
			url,
			locals: { authServer: { handleCallback } },
			request: new Request(url, {
				method: 'POST',
				body: new URLSearchParams({
					email: ' user@example.com ',
					password: ' password ',
					confirmPassword: ' password '
				})
			})
		};
		const pending = actions.default(event as unknown as Parameters<typeof actions.default>[0]);
		if (kind === 'redirect')
			await expect(pending).rejects.toMatchObject({ status: 303, location: '/dashboard' });
		else {
			const result = await pending;
			expect(result).toMatchObject(
				error
					? { status: 400, data: { complete: false, needsEmail: kind === 'auth/missing-email' } }
					: { complete: true, message: 'Done' }
			);
		}
		expect(handleCallback).toHaveBeenCalledWith(url, {
			email: 'user@example.com',
			newPassword: ' password ',
			confirmPassword: ' password '
		});
	}
);

it('rejects invalid callback fields before consuming the link', async () => {
	const handleCallback = vi.fn();
	const url = new URL('https://app/auth/callback?mode=signIn&oobCode=code');
	const event = {
		url,
		locals: { authServer: { handleCallback } },
		request: new Request(url, { method: 'POST', body: new URLSearchParams({ email: 'invalid' }) })
	};
	const { status, data } = (await actions.default(
		event as unknown as Parameters<typeof actions.default>[0]
	)) as { status: number; data: { needsEmail: boolean } };
	expect(status).toBe(400);
	expect(data.needsEmail).toBe(true);
	expect(handleCallback).not.toHaveBeenCalled();
});
