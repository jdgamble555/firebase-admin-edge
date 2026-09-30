import { describe, expect, it, vi } from 'vitest';
import { load } from './+layout.server';

describe('root layout session', () => {
	it('preserves the error message in the serialized response', async () => {
		const firebaseError = new Error('Session signature verification failed', {
			cause: new Error('Invalid signature')
		});
		const getUser = vi.fn().mockResolvedValue({ data: null, error: firebaseError });
		const event = { locals: { fbServer: { getUser } } };

		const result = load(event as unknown as Parameters<typeof load>[0]);
		const failure = await result.catch((error) => error);
		const body = JSON.parse(JSON.stringify(failure.body));

		expect(failure.status).toBe(400);
		expect(body).toEqual({ message: firebaseError.message });
	});

	it.each([null, { uid: 'user-123' }])('returns the current user: %j', async (user) => {
		const getUser = vi.fn().mockResolvedValue({ data: user, error: null });
		const event = { locals: { fbServer: { getUser } } };

		const result = await load(event as unknown as Parameters<typeof load>[0]);

		expect(result).toEqual({ user });
	});
});
