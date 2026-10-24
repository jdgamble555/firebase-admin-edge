import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
    RemoteConfig,
    RemoteConfigTemplate,
    ServerTemplate
} from './remote-config.js';
import { getToken } from '../auth/google-oauth.js';
import { remoteConfigRequest } from './remote-config-endpoints.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

vi.mock('../auth/google-oauth.js');
vi.mock('./remote-config-endpoints.js');
const account = {
    project_id: 'project',
    client_email: 'admin@example.com'
} as ServiceAccount;
const data = {
    etag: 'tag',
    parameters: {},
    parameterGroups: {},
    conditions: []
};

beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(getToken).mockResolvedValue({
        error: null,
        data: {
            access_token: 'access',
            expires_in: 3600,
            token_type: 'Bearer',
            scope: 'scope',
            id_token: ''
        }
    });
    vi.mocked(remoteConfigRequest).mockResolvedValue(data);
});

describe('RemoteConfig', () => {
    it('requires a project ID', () => {
        expect(() => new RemoteConfig({} as ServiceAccount)).toThrow(
            'project ID'
        );
    });

    it('coordinates every management method and custom fetch', async () => {
        const fetch = vi.fn();
        const config = new RemoteConfig(account, { fetch });
        const calls = [
            [() => config.getTemplate(), { type: 'get' }],
            [
                () => config.getTemplateAtVersion('12'),
                { type: 'get', version: '12' }
            ],
            [
                () => config.validateTemplate(data),
                { type: 'validate', template: data }
            ],
            [
                () => config.publishTemplate(data, { force: true }),
                { type: 'publish', template: data, force: true }
            ],
            [() => config.rollback(3), { type: 'rollback', version: 3 }]
        ] as const;
        for (const [call, operation] of calls) {
            const { error, data: template } = await call();
            expect(error).toBeNull();
            expect(template).toBeInstanceOf(RemoteConfigTemplate);
            expect(remoteConfigRequest).toHaveBeenLastCalledWith(
                'project',
                'access',
                operation,
                fetch
            );
        }
        vi.mocked(remoteConfigRequest).mockResolvedValue({ versions: [] });
        const { data: versions } = await config.listVersions({ pageSize: 5 });
        expect(versions).toEqual({ versions: [] });
    });

    it('uses shared token cache and namespace', async () => {
        const cache = { getCache: vi.fn(), setCache: vi.fn() };
        const config = new RemoteConfig(account, {
            cache,
            cacheName: 'custom'
        });
        await config.getTemplate();
        expect(cache.setCache).toHaveBeenCalledWith(
            'custom:remote-config:admin@example.com',
            expect.objectContaining({ access_token: 'access' }),
            3540000
        );
        cache.getCache.mockReturnValue({ access_token: 'cached' });
        await config.getTemplate();
        expect(getToken).toHaveBeenCalledTimes(1);
        expect(remoteConfigRequest).toHaveBeenLastCalledWith(
            'project',
            'cached',
            { type: 'get' },
            globalThis.fetch
        );
    });

    it('does not cache tokens with unusable expiry', async () => {
        vi.mocked(getToken).mockResolvedValue({
            error: null,
            data: {
                access_token: 'access',
                expires_in: 10,
                token_type: 'Bearer',
                scope: 'scope',
                id_token: ''
            }
        });
        const cache = { getCache: vi.fn(), setCache: vi.fn() };
        await new RemoteConfig(account, { cache }).getTemplate();
        expect(cache.setCache).not.toHaveBeenCalled();
    });

    it('returns token, endpoint, and cache failures through results', async () => {
        const failure = new FirebaseEdgeError({
            code: 'test/failure',
            message: 'failed'
        });
        vi.mocked(getToken).mockResolvedValueOnce({
            error: failure,
            data: null
        });
        const config = new RemoteConfig(account);
        const evaluationResult1 = await config.getTemplate();
        expect(evaluationResult1).toEqual({ error: failure, data: null });
        expect(remoteConfigRequest).not.toHaveBeenCalled();
        vi.mocked(remoteConfigRequest).mockRejectedValueOnce(failure);
        const evaluationResult2 = await config.getTemplate();
        expect(evaluationResult2).toEqual({ error: failure, data: null });
        const cache = {
            getCache: vi.fn().mockRejectedValue(failure),
            setCache: vi.fn()
        };
        const evaluationResult3 = await new RemoteConfig(account, {
            cache
        }).getTemplate();
        expect(evaluationResult3).toEqual({ error: failure, data: null });
    });

    it('creates JSON templates and reports invalid inputs', () => {
        const config = new RemoteConfig(account);
        const { error, data: template } = config.createTemplateFromJSON(
            JSON.stringify({ etag: 'tag' })
        );
        expect(error).toBeNull();
        expect(template?.toJSON()).toMatchObject(data);
        for (const json of ['', '{', 'null', '[]', '{}']) {
            expect(config.createTemplateFromJSON(json).error?.code).toBe(
                'remote-config/invalid-argument'
            );
        }
    });

    it('loads and initializes server templates, preserving failures', async () => {
        const config = new RemoteConfig(account);
        expect(config.initServerTemplate({ template: data })).toBeInstanceOf(
            ServerTemplate
        );
        const { error, data: template } = await config.getServerTemplate();
        expect(error).toBeNull();
        expect(template?.toJSON()).toMatchObject(data);
        expect(remoteConfigRequest).toHaveBeenLastCalledWith(
            'project',
            'access',
            { type: 'server' },
            globalThis.fetch
        );
        vi.mocked(remoteConfigRequest).mockRejectedValueOnce(
            new Error('offline')
        );
        const evaluationResult4 = await config.getServerTemplate();
        expect(evaluationResult4.error).toBeInstanceOf(FirebaseEdgeError);
        const evaluationResult5 = await config.getServerTemplate(null as never);
        expect(evaluationResult5.error).toBeInstanceOf(FirebaseEdgeError);
    });

    it('rejects invalid publish options', async () => {
        const { error } = await new RemoteConfig(account).publishTemplate(
            data,
            null as never
        );
        expect(error?.code).toBe('remote-config/invalid-argument');
    });
});
