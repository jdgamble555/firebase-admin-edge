import { expect, it, vi } from 'vitest';
import {
    IdentityProviders,
    parseIdentityProvidersPage
} from './identity-providers.js';
import { FirebaseAdminAuth } from './firebase-admin-auth.js';
import type { ServiceAccount } from './firebase-types.js';

it('delegates reads and errors to the configured auth client', async () => {
    const auth = new FirebaseAdminAuth({ project_id: 'p' } as ServiceAccount);
    const get = vi.spyOn(auth, '_getProviders');
    const providers = new IdentityProviders(auth);
    get.mockResolvedValueOnce({
        data: [{ providerId: 'google.com', enabled: true }],
        error: null
    });
    const result = await providers.get();
    expect(result).toEqual({
        data: [{ providerId: 'google.com', enabled: true }],
        error: null
    });
    const error = new Error('denied');
    get.mockResolvedValueOnce({ data: null, error });
    const failure = await providers.get();
    expect(failure).toEqual({ data: null, error });
});

it('filters disabled providers and strips credentials from project and tenant configurations', () => {
    expect(
        parseIdentityProvidersPage({
            defaultSupportedIdpConfigs: [
                {
                    name: 'projects/p/defaultSupportedIdpConfigs/google.com',
                    enabled: true,
                    clientSecret: 'secret',
                    clientId: 'id'
                },
                {
                    name: 'projects/p/tenants/t/defaultSupportedIdpConfigs/apple.com',
                    enabled: true,
                    appleSignInConfig: { privateKey: 'secret' }
                },
                {
                    name: 'projects/p/defaultSupportedIdpConfigs/github.com',
                    enabled: false
                },
                { name: 'projects/p/defaultSupportedIdpConfigs/facebook.com' }
            ],
            nextPageToken: 'next'
        })
    ).toEqual({
        providers: [
            { providerId: 'google.com', enabled: true },
            { providerId: 'apple.com', enabled: true }
        ],
        nextPageToken: 'next'
    });
    expect(parseIdentityProvidersPage({})).toEqual({
        providers: [],
        nextPageToken: undefined
    });
});

it.each([
    null,
    [],
    'invalid',
    { nextPageToken: 1 },
    { defaultSupportedIdpConfigs: {} },
    ...[
        null,
        [],
        {},
        { name: 'google.com', enabled: true },
        {
            name: 'projects/p/defaultSupportedIdpConfigs/google.com',
            enabled: 'true'
        }
    ].map((config) => ({ defaultSupportedIdpConfigs: [config] }))
])('rejects malformed provider responses: %j', (value) => {
    expect(() => parseIdentityProvidersPage(value)).toThrow();
});
