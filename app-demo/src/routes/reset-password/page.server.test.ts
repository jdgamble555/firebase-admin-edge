import { expect, it, vi } from 'vitest';
import { actions } from './+page.server';

it.each([
	'success',
	'auth/endpoint-user-not-found',
	'auth/invalid-email',
	'auth/too-many-requests'
])('handles reset delivery: %s', async (code) => {
	const sendPasswordResetEmail = vi.fn().mockResolvedValue({
		error: code === 'success' ? null : { code, message: 'Cannot send email' }
	});
	const event = {
		locals: { authServer: { sendPasswordResetEmail } },
		request: new Request('https://app/reset-password', {
			method: 'POST',
			body: new URLSearchParams({ email: ' user@example.com ' })
		})
	};
	const result = await actions.default(event as unknown as Parameters<typeof actions.default>[0]);
	expect(sendPasswordResetEmail).toHaveBeenCalledWith('user@example.com');
	expect(result).toMatchObject(
		code === 'success' || code === 'auth/endpoint-user-not-found'
			? { sent: true }
			: { status: 400, data: { sent: false } }
	);
});

it.each(['', 'invalid', ' '])(
	'rejects invalid email before contacting Firebase: %s',
	async (email) => {
		const sendPasswordResetEmail = vi.fn();
		const event = {
			locals: { authServer: { sendPasswordResetEmail } },
			request: new Request('https://app/reset-password', {
				method: 'POST',
				body: new URLSearchParams({ email })
			})
		};
		const { status } = (await actions.default(
			event as unknown as Parameters<typeof actions.default>[0]
		)) as { status: number };
		expect(status).toBe(400);
		expect(sendPasswordResetEmail).not.toHaveBeenCalled();
	}
);
