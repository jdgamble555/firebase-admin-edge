import { describe, expect, it, vi } from 'vitest';
import { actions, load } from './+page.server';

describe('dashboard', () => {
	it('combines enabled providers with linked identities without offering disabled providers', async () => {
		const get = vi.fn().mockResolvedValue({
			error: null,
			data: [
				{ providerId: 'google.com', enabled: true },
				{ providerId: 'apple.com', enabled: true },
				{ providerId: 'playgames.google.com', enabled: true }
			]
		});
		const event = {
			url: new URL('https://app/dashboard'),
			locals: { fbServer: { identity: { providers: { get } } } },
			parent: vi.fn().mockResolvedValue({
				user: {
					firebase: {
						identities: {
							'google.com': ['google-user'],
							'github.com': ['github-user'],
							email: ['user@example.com'],
							'facebook.com': [],
							unknown: ['unknown-user']
						}
					}
				}
			})
		};
		const result = await load(event as unknown as Parameters<typeof load>[0]);
		expect(result).toEqual({
			providers: { 'google.com': true, 'apple.com': false, 'github.com': true, email: true }
		});
		expect(get).toHaveBeenCalledOnce();
	});

	it('returns an empty provider list when none are enabled or linked', async () => {
		const event = {
			url: new URL('https://app/dashboard'),
			locals: {
				fbServer: {
					identity: { providers: { get: vi.fn().mockResolvedValue({ error: null, data: [] }) } }
				}
			},
			parent: vi.fn().mockResolvedValue({ user: { firebase: { identities: {} } } })
		};
		const result = await load(event as unknown as Parameters<typeof load>[0]);
		expect(result).toEqual({ providers: {} });
	});

	it('reports provider discovery failures through SvelteKit error', async () => {
		const event = {
			url: new URL('https://app/dashboard'),
			locals: {
				fbServer: {
					identity: {
						providers: {
							get: vi
								.fn()
								.mockResolvedValue({ error: new Error('Provider lookup failed'), data: null })
						}
					}
				}
			},
			parent: vi.fn().mockResolvedValue({ user: { firebase: { identities: {} } } })
		};
		const result = load(event as unknown as Parameters<typeof load>[0]);
		await expect(result).rejects.toMatchObject({
			status: 500,
			body: { message: 'Provider lookup failed' }
		});
	});

	it.each([false, true])(
		'does not link when provider discovery fails or provider is disabled (failure=%s)',
		async (failure) => {
			const getProviderLinkURL = vi.fn();
			const event = {
				url: new URL('https://app/dashboard'),
				locals: {
					fbServer: {
						getProviderLinkURL,
						identity: {
							providers: {
								get: vi
									.fn()
									.mockResolvedValue(
										failure
											? { error: new Error('Provider lookup failed'), data: null }
											: { error: null, data: [] }
									)
							}
						}
					}
				},
				request: new Request('https://app/dashboard?/addProvider', {
					method: 'POST',
					body: new URLSearchParams({ provider: 'google.com' })
				})
			};
			const result = await actions.addProvider(
				event as unknown as Parameters<typeof actions.addProvider>[0]
			);
			expect(result).toMatchObject({
				status: failure ? 500 : 400,
				data: { message: failure ? 'Provider lookup failed' : 'Provider is not enabled.' }
			});
			expect(getProviderLinkURL).not.toHaveBeenCalled();
		}
	);

	it('redirects visitors without a session', async () => {
		const event = {
			url: new URL('http://localhost:5173/dashboard'),
			parent: vi.fn().mockResolvedValue({ user: null })
		};

		const result = load(event as unknown as Parameters<typeof load>[0]);

		await expect(result).rejects.toMatchObject({ status: 302, location: '/' });
	});

	it.each(['google.com', 'github.com', 'apple.com', 'microsoft.com'])(
		'starts linking %s',
		async (provider) => {
			const fbServer = {
				identity: {
					providers: {
						get: vi
							.fn()
							.mockResolvedValue({ error: null, data: [{ providerId: provider, enabled: true }] })
					}
				},
				getProviderLinkURL: vi.fn().mockResolvedValue('https://provider/login')
			};
			const event = {
				url: new URL('http://localhost:5173/dashboard'),
				locals: { fbServer },
				request: new Request('http://localhost:5173/dashboard?/addProvider', {
					method: 'POST',
					body: new URLSearchParams({ provider })
				})
			};

			const result = actions.addProvider(
				event as unknown as Parameters<typeof actions.addProvider>[0]
			);

			await expect(result).rejects.toMatchObject({
				status: 302,
				location: 'https://provider/login'
			});
			expect(fbServer.getProviderLinkURL).toHaveBeenCalledWith(provider, '/dashboard');
		}
	);

	it('returns a form failure for unsupported providers', async () => {
		const event = {
			url: new URL('http://localhost:5173/dashboard'),
			locals: { fbServer: {} },
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
			locals: { fbServer: { unlinkProvider } },
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
