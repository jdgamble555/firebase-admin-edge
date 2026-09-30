import { expect, it, vi } from 'vitest';
import { actions, load } from './+page.server';

it('redirects visitors without a session', async () => {
	const event = { parent: vi.fn().mockResolvedValue({ user: null }) };
	const result = load(event as unknown as Parameters<typeof load>[0]);
	await expect(result).rejects.toMatchObject({ status: 302, location: '/' });
});

it('allows signed-in users to load the form', async () => {
	const event = { parent: vi.fn().mockResolvedValue({ user: { uid: 'user' } }) };
	const result = await load(event as unknown as Parameters<typeof load>[0]);
	expect(result).toEqual({});
});

it('rejects direct form submissions without a session', async () => {
	const verifyBeforeUpdateEmail = vi.fn();
	const formData = vi.fn();
	const event = {
		locals: {
			fbServer: { getUser: vi.fn().mockResolvedValue({ data: null }), verifyBeforeUpdateEmail }
		},
		request: { formData }
	};
	const result = actions.changeEmail(event as unknown as Parameters<typeof actions.changeEmail>[0]);
	await expect(result).rejects.toMatchObject({ status: 302, location: '/' });
	expect(formData).not.toHaveBeenCalled();
	expect(verifyBeforeUpdateEmail).not.toHaveBeenCalled();
});

it.each([false, true])('requests a verified email change (failure=%s)', async (failure) => {
	const verifyBeforeUpdateEmail = vi
		.fn()
		.mockResolvedValue({ error: failure ? { message: 'Sign in again' } : null });
	const event = {
		locals: {
			fbServer: {
				verifyBeforeUpdateEmail,
				getUser: vi.fn().mockResolvedValue({ data: { uid: 'user' } })
			}
		},
		request: new Request('https://app/change-email', {
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
			locals: {
				fbServer: {
					verifyBeforeUpdateEmail,
					getUser: vi.fn().mockResolvedValue({ data: { uid: 'user' } })
				}
			},
			request: new Request('https://app/change-email', {
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
