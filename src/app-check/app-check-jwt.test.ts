import { beforeAll, beforeEach, expect, it, vi } from 'vitest';
import {
    generateKeyPair,
    exportPKCS8,
    exportJWK,
    SignJWT,
    jwtVerify,
    type JWTPayload
} from 'jose';
import { signAppCheckToken, verifyAppCheckToken } from './app-check-jwt.js';
import { createAppCheckKeyResolver } from './app-check-endpoints.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

let keys: Awaited<ReturnType<typeof generateKeyPair>>;
let account: ServiceAccount;
let resolver: ReturnType<typeof createAppCheckKeyResolver>;
let claims: JWTPayload;
beforeAll(async () => {
    keys = await generateKeyPair('RS256', { extractable: true });
    const privateKey = await exportPKCS8(keys.privateKey);
    account = {
        private_key: privateKey,
        client_email: 'service@example.com'
    } as ServiceAccount;
    const jwk = await exportJWK(keys.publicKey);
    resolver = createAppCheckKeyResolver(
        vi
            .fn()
            .mockResolvedValue(
                Response.json({ keys: [{ ...jwk, kid: 'key' }] })
            )
    );
});
beforeEach(() => {
    const now = Math.floor(Date.now() / 1000);
    claims = {
        iss: 'https://firebaseappcheck.googleapis.com/123',
        aud: ['projects/demo', 'projects/123'],
        sub: 'app',
        iat: now,
        exp: now + 3600
    };
});

it.each([undefined, 1800000, 604800000])(
    'signs a custom provider assertion with TTL %s',
    async (ttl) => {
        const token = await signAppCheckToken(account, 'app', ttl);
        const { payload, protectedHeader } = await jwtVerify(
            token,
            keys.publicKey
        );
        expect(protectedHeader).toEqual({ alg: 'RS256', typ: 'JWT' });
        expect(payload).toMatchObject({
            app_id: 'app',
            iss: account.client_email,
            sub: account.client_email,
            aud: 'https://firebaseappcheck.googleapis.com/google.firebase.appcheck.v1.TokenExchangeService'
        });
        expect(payload.exp! - payload.iat!).toBe(300);
        expect(payload.ttl).toBe(
            ttl === undefined ? undefined : `${ttl / 1000}s`
        );
    }
);
it.each([0, 1799999, 604800001, NaN, Infinity])(
    'rejects invalid TTL %s',
    async (ttl) => {
        const operation = signAppCheckToken(account, 'app', ttl);
        await expect(operation).rejects.toMatchObject({
            code: 'app-check/invalid-argument'
        });
    }
);
it('rejects missing app IDs before signing', async () => {
    const operation = signAppCheckToken(account, ' ');
    await expect(operation).rejects.toMatchObject({
        code: 'app-check/invalid-argument'
    });
});
it('supports escaped newlines in service account keys', async () => {
    const token = await signAppCheckToken(
        { ...account, private_key: account.private_key.replace(/\n/g, '\\n') },
        'app'
    );
    const { payload } = await jwtVerify(token, keys.publicKey);
    expect(payload.app_id).toBe('app');
});
it('verifies a signed token and derives app_id from its subject', async () => {
    const token = await new SignJWT({ ...claims, app_id: 'untrusted' })
        .setProtectedHeader({ alg: 'RS256', kid: 'key' })
        .sign(keys.privateKey);
    const decoded = await verifyAppCheckToken(token, 'demo', resolver);
    expect(decoded).toEqual({ ...claims, app_id: 'app' });
});
it.each([
    { aud: ['projects/other'] },
    { aud: 'projects/demo' },
    { iss: 'https://evil.example/123' },
    { iss: 'https://firebaseappcheck.googleapis.com/' },
    { sub: '' },
    { sub: 42 },
    { exp: 1 },
    { exp: undefined },
    { iat: undefined },
    { iat: 9999999999 }
])('rejects invalid claims %j', async (overrides) => {
    const token = await new SignJWT({ ...claims, ...overrides } as JWTPayload)
        .setProtectedHeader({ alg: 'RS256', kid: 'key' })
        .sign(keys.privateKey);
    const operation = verifyAppCheckToken(token, 'demo', resolver);
    await expect(operation).rejects.toBeInstanceOf(Error);
});
it.each(['', 'malformed', 'eyJhbGciOiJub25lIn0.e30.'])(
    'rejects invalid tokens %s',
    async (token) => {
        const operation = verifyAppCheckToken(token, 'demo', resolver);
        await expect(operation).rejects.toBeInstanceOf(Error);
    }
);
it('rejects forged signatures', async () => {
    const otherKeys = await generateKeyPair('RS256');
    const token = await new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: 'key' })
        .sign(otherKeys.privateKey);
    const operation = verifyAppCheckToken(token, 'demo', resolver);
    await expect(operation).rejects.toBeInstanceOf(Error);
});
