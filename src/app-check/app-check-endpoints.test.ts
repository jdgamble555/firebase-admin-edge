import { expect, it, vi } from 'vitest';
import {
    appCheckRequest,
    createAppCheckKeyResolver,
    parseAppCheckToken
} from './app-check-endpoints.js';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify } from 'jose';

it('fetches and caches App Check signing keys using the injected fetch', async () => {
    const keys = await generateKeyPair('RS256');
    const jwk = await exportJWK(keys.publicKey);
    const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ keys: [{ ...jwk, kid: 'key' }] }));
    const resolver = createAppCheckKeyResolver(fetch);
    const token = await new SignJWT({})
        .setProtectedHeader({ alg: 'RS256', kid: 'key' })
        .sign(keys.privateKey);
    await jwtVerify(token, resolver);
    await jwtVerify(token, resolver);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(String(fetch.mock.calls[0]?.[0])).toBe(
        'https://firebaseappcheck.googleapis.com/v1/jwks'
    );
});
it.each([
    [
        { appId: 'app/id', customToken: 'signed' },
        'v1/projects/demo%2Fproject/apps/app%2Fid:exchangeCustomToken',
        { customToken: 'signed' }
    ],
    [
        { token: 'signed' },
        'v1beta/projects/demo%2Fproject:verifyAppCheckToken',
        { app_check_token: 'signed' }
    ]
] as const)('constructs the request for %j', async (operation, path, body) => {
    const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ token: 'token', ttl: '3600s' }));
    await appCheckRequest('demo/project', 'access', operation, fetch);
    expect(fetch).toHaveBeenCalledWith(
        `https://firebaseappcheck.googleapis.com/${path}`,
        expect.objectContaining({
            method: 'POST',
            body: JSON.stringify(body),
            headers: expect.objectContaining({ Authorization: 'Bearer access' })
        })
    );
});
it.each([
    [{}, { customToken: 'signed' }],
    [{ limitedUse: undefined, jti: undefined }, { customToken: 'signed' }],
    [{ limitedUse: false }, { customToken: 'signed', limitedUse: false }],
    [{ limitedUse: true }, { customToken: 'signed', limitedUse: true }],
    [
        { limitedUse: true, jti: 'operation-123' },
        { customToken: 'signed', limitedUse: true, jti: 'operation-123' }
    ],
    [
        { limitedUse: true, jti: '' },
        { customToken: 'signed', limitedUse: true, jti: '' }
    ]
] as const)('serializes token exchange options %j', async (options, body) => {
    const fetch = vi
        .fn()
        .mockResolvedValue(Response.json({ token: 'token', ttl: '3600s' }));

    await appCheckRequest(
        'demo',
        'access',
        { appId: 'app', customToken: 'signed', ...options },
        fetch
    );

    expect(fetch).toHaveBeenCalledWith(
        'https://firebaseappcheck.googleapis.com/v1/projects/demo/apps/app:exchangeCustomToken',
        expect.objectContaining({ body: JSON.stringify(body) })
    );
});
it.each([
    'PERMISSION_DENIED',
    'INVALID_ARGUMENT',
    'UNAUTHENTICATED',
    'NOT_FOUND',
    'RESOURCE_EXHAUSTED',
    'UNKNOWN'
])('maps API error %s', async (status) => {
    const fetch = vi
        .fn()
        .mockResolvedValue(
            Response.json(
                { error: { status, message: 'failed' } },
                { status: 400 }
            )
        );
    const operation = appCheckRequest(
        'demo',
        'access',
        { token: 'token' },
        fetch
    );
    await expect(operation).rejects.toMatchObject({
        code: `app-check/${status === 'UNKNOWN' ? 'unknown-error' : status.toLowerCase().replaceAll('_', '-')}`,
        message: 'failed'
    });
});
it('rejects non-JSON errors and malformed successful responses', async () => {
    const fetch = vi
        .fn()
        .mockResolvedValueOnce(new Response('unavailable', { status: 503 }))
        .mockResolvedValueOnce(Response.json(null));
    const failed = appCheckRequest('demo', 'access', { token: 'token' }, fetch);
    await expect(failed).rejects.toMatchObject({
        code: 'app-check/unknown-error'
    });
    const malformed = appCheckRequest(
        'demo',
        'access',
        { token: 'token' },
        fetch
    );
    await expect(malformed).rejects.toMatchObject({
        code: 'app-check/internal-error'
    });
});
it('converts fractional duration to milliseconds', () => {
    expect(
        parseAppCheckToken({ token: 'token', ttl: '3600.123456789s' })
    ).toEqual({ token: 'token', ttlMillis: 3600123 });
});
it.each([
    {},
    { token: '', ttl: '1s' },
    { token: 't', ttl: '0s' },
    { token: 't', ttl: 'NaNs' },
    { token: 't', ttl: '123' },
    { token: 't', ttl: '999999999999999999s' }
])('rejects invalid token response %j', (response) => {
    expect(() => parseAppCheckToken(response)).toThrow();
});
