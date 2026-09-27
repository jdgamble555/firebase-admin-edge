import { beforeEach, expect, it, vi } from 'vitest';
import { errors } from 'jose';
import { AppCheck } from './app-check.js';
import { getToken } from '../auth/google-oauth.js';
import { signAppCheckToken, verifyAppCheckToken } from './app-check-jwt.js';
import { appCheckRequest } from './app-check-endpoints.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

vi.mock('../auth/google-oauth.js');
vi.mock('./app-check-jwt.js');
vi.mock('./app-check-endpoints.js', async (original) => {
    const actual = await original<typeof import('./app-check-endpoints.js')>();
    return { ...actual, appCheckRequest: vi.fn() };
});
const account = {
    project_id: 'demo',
    client_email: 'service@example.com'
} as ServiceAccount;
const fetch = vi.fn();
const oauth = { access_token: 'access', expires_in: 3600 } as never;
beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(getToken).mockResolvedValue({ error: null, data: oauth });
    vi.mocked(signAppCheckToken).mockResolvedValue('assertion');
    vi.mocked(verifyAppCheckToken).mockResolvedValue({
        app_id: 'app'
    } as never);
    vi.mocked(appCheckRequest).mockResolvedValue({
        token: 'token',
        ttl: '3600s'
    });
});
it('requires a project ID', () => {
    expect(() => new AppCheck({} as ServiceAccount)).toThrow();
});
it('creates tokens and reuses cached production credentials', async () => {
    const cache = {
        getCache: vi.fn().mockReturnValueOnce(undefined).mockReturnValue(oauth),
        setCache: vi.fn()
    };
    const appCheck = new AppCheck(account, fetch, cache, 'custom');
    const { error, data } = await appCheck.createToken('app', {
        ttlMillis: 1800000
    });
    expect(error).toBeNull();
    expect(data).toEqual({ token: 'token', ttlMillis: 3600000 });
    expect(signAppCheckToken).toHaveBeenCalledWith(account, 'app', 1800000);
    expect(appCheckRequest).toHaveBeenCalledWith(
        'demo',
        'access',
        { appId: 'app', customToken: 'assertion' },
        fetch
    );
    expect(cache.setCache).toHaveBeenCalledWith(
        'custom:app-check:service@example.com',
        oauth,
        3540000
    );
    await appCheck.createToken('app');
    expect(getToken).toHaveBeenCalledTimes(1);
    expect(getToken).toHaveBeenCalledWith(account, fetch);
});
it('verifies without fetching credentials or consuming by default', async () => {
    const { error, data } = await new AppCheck(account, fetch).verifyToken(
        'token'
    );
    expect(error).toBeNull();
    expect(data).toEqual({ appId: 'app', token: { app_id: 'app' } });
    expect(getToken).not.toHaveBeenCalled();
    expect(appCheckRequest).not.toHaveBeenCalled();
});
it.each([
    {},
    { limitedUse: undefined, jti: undefined },
    { limitedUse: false },
    { limitedUse: true },
    { limitedUse: true, jti: 'operation-123' },
    { limitedUse: true, jti: '' }
])('forwards token exchange options %j', async (options) => {
    const { error, data } = await new AppCheck(account, fetch).createToken(
        'app',
        {
            ttlMillis: 1800000,
            ...options
        }
    );

    expect(error).toBeNull();
    expect(data).toEqual({ token: 'token', ttlMillis: 3600000 });
    expect(signAppCheckToken).toHaveBeenCalledWith(account, 'app', 1800000);
    expect(appCheckRequest).toHaveBeenCalledWith(
        'demo',
        'access',
        {
            appId: 'app',
            customToken: 'assertion',
            ...(options.limitedUse !== undefined && {
                limitedUse: options.limitedUse
            }),
            ...(options.jti !== undefined && { jti: options.jti })
        },
        fetch
    );
});
it.each([
    { limitedUse: 'true' },
    { limitedUse: 1 },
    { limitedUse: null },
    { limitedUse: true, jti: 123 },
    { limitedUse: true, jti: null },
    { limitedUse: true, jti: {} },
    { jti: 'operation-123' },
    { jti: '' },
    { limitedUse: false, jti: 'operation-123' },
    { limitedUse: false, jti: '' }
])(
    'rejects invalid token options before signing or fetching: %j',
    async (options) => {
        const { error, data } = await new AppCheck(account, fetch).createToken(
            'app',
            options as never
        );

        expect(error?.code).toBe('app-check/invalid-argument');
        expect(data).toBeNull();
        expect(signAppCheckToken).not.toHaveBeenCalled();
        expect(getToken).not.toHaveBeenCalled();
        expect(appCheckRequest).not.toHaveBeenCalled();
        expect(fetch).not.toHaveBeenCalled();
    }
);
it('does not cache credentials with an unusable lifetime', async () => {
    vi.mocked(getToken).mockResolvedValue({
        error: null,
        data: { access_token: 'access', expires_in: 30 } as never
    });
    const cache = { getCache: vi.fn(), setCache: vi.fn() };
    const { error } = await new AppCheck(account, fetch, cache).createToken(
        'app'
    );
    expect(error).toBeNull();
    expect(cache.setCache).not.toHaveBeenCalled();
});
it.each([true, false, undefined])(
    'returns replay status %s',
    async (alreadyConsumed) => {
        vi.mocked(appCheckRequest).mockResolvedValue({ alreadyConsumed });
        const { error, data } = await new AppCheck(account, fetch).verifyToken(
            'token',
            { consume: true }
        );
        expect(error).toBeNull();
        expect(data?.alreadyConsumed).toBe(alreadyConsumed ?? false);
        expect(appCheckRequest).toHaveBeenCalledWith(
            'demo',
            'access',
            { token: 'token' },
            fetch
        );
    }
);
it('rejects malformed replay status', async () => {
    vi.mocked(appCheckRequest).mockResolvedValue({
        alreadyConsumed: 'false'
    } as never);
    const { error } = await new AppCheck(account, fetch).verifyToken('token', {
        consume: true
    });
    expect(error?.code).toBe('app-check/internal-error');
});
it.each([null, [], { consume: 'true' }])(
    'rejects invalid verification options %j',
    async (options) => {
        const { error } = await new AppCheck(account).verifyToken(
            'token',
            options as never
        );
        expect(error?.code).toBe('app-check/invalid-argument');
        expect(verifyAppCheckToken).not.toHaveBeenCalled();
    }
);
it('rejects null creation options', async () => {
    const { error } = await new AppCheck(account).createToken(
        'app',
        null as never
    );
    expect(error?.code).toBe('app-check/invalid-argument');
});
it.each(['create', 'consume'])(
    'propagates credential errors for %s',
    async (operation) => {
        const failure = new FirebaseEdgeError({
            code: 'google/failed',
            message: 'failed'
        });
        vi.mocked(getToken).mockResolvedValue({ error: failure, data: null });
        const appCheck = new AppCheck(account);
        const { error, data } =
            operation === 'create'
                ? await appCheck.createToken('app')
                : await appCheck.verifyToken('token', { consume: true });
        expect(error).toBe(failure);
        expect(data).toBeNull();
        expect(appCheckRequest).not.toHaveBeenCalled();
    }
);
it.each([
    [new errors.JWTExpired('expired', {}), 'app-check/app-check-token-expired'],
    [new errors.JWSSignatureVerificationFailed(), 'app-check/invalid-argument'],
    [new Error('network'), 'app-check/internal-error']
])('maps verification failures', async (cause, code) => {
    vi.mocked(verifyAppCheckToken).mockRejectedValue(cause);
    const { error, data } = await new AppCheck(account).verifyToken('token', {
        consume: true
    });
    expect(error?.code).toBe(code);
    expect(data).toBeNull();
    expect(appCheckRequest).not.toHaveBeenCalled();
});
it('returns signing and request failures as results', async () => {
    vi.mocked(signAppCheckToken).mockRejectedValueOnce(new Error('bad key'));
    const appCheck = new AppCheck(account);
    const { error: signingError } = await appCheck.createToken('app');
    expect(signingError?.code).toBe('app-check/internal-error');
    const failure = new FirebaseEdgeError({
        code: 'app-check/permission-denied',
        message: 'denied'
    });
    vi.mocked(appCheckRequest).mockRejectedValue(failure);
    const { error } = await appCheck.createToken('app');
    expect(error).toBe(failure);
});
