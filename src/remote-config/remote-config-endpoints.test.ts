import { describe, expect, it, vi } from 'vitest';
import {
    remoteConfigRequest,
    remoteConfigListParams
} from './remote-config-endpoints.js';
import type { RemoteConfigOperation } from './remote-config-endpoints.js';

const template = {
    etag: 'old',
    parameters: {},
    parameterGroups: {},
    conditions: [],
    version: { versionNumber: '2', description: 'release' }
};
function response(
    body: object = {},
    etag: string | null = 'new',
    status = 200
) {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            'Content-Type': 'application/json',
            ...(etag && { ETag: etag })
        }
    });
}

describe('remoteConfigRequest', () => {
    it.each([
        [{ type: 'get' }, '/remoteConfig', 'GET'],
        [
            { type: 'get', version: '9223372036854775807' },
            '/remoteConfig?versionNumber=9223372036854775807',
            'GET'
        ],
        [{ type: 'rollback', version: 2 }, '/remoteConfig:rollback', 'POST'],
        [
            { type: 'list', options: { pageSize: 5 } },
            '/remoteConfig:listVersions?pageSize=5',
            'GET'
        ],
        [
            { type: 'server' },
            '/namespaces/firebase-server/serverRemoteConfig',
            'GET'
        ]
    ] as const)(
        'sends %j to its REST endpoint',
        async (operation, suffix, method) => {
            const fetch = vi.fn().mockResolvedValue(response());
            const data = await remoteConfigRequest(
                'project/a',
                'token',
                operation,
                fetch
            );
            expect(fetch).toHaveBeenCalledWith(
                `https://firebaseremoteconfig.googleapis.com/v1/projects/project%2Fa${suffix}`,
                expect.objectContaining({
                    method,
                    headers: expect.objectContaining({
                        Authorization: 'Bearer token',
                        'Accept-Encoding': 'gzip'
                    })
                })
            );
            expect(data).toMatchObject(
                operation.type === 'list' ? { versions: [] } : { etag: 'new' }
            );
            if (operation.type === 'rollback') {
                expect(JSON.parse(fetch.mock.calls[0]![1].body)).toEqual({
                    versionNumber: '2'
                });
            }
            if (method === 'GET') {
                expect(fetch.mock.calls[0]![1].body).toBeUndefined();
            }
        }
    );

    it('publishes with ETag, strips output metadata, and supports force', async () => {
        const fetch = vi.fn().mockImplementation(() => response());
        for (const force of [false, true]) {
            await remoteConfigRequest(
                'p',
                't',
                { type: 'publish', template, force },
                fetch
            );
            const [, init] = fetch.mock.calls.at(-1)!;
            expect(init.method).toBe('PUT');
            expect(init.headers['If-Match']).toBe(force ? '*' : 'old');
            expect(JSON.parse(init.body)).toEqual({
                conditions: [],
                parameters: {},
                parameterGroups: {},
                version: { description: 'release' }
            });
        }
        expect(template.version.versionNumber).toBe('2');
    });

    it('validates without replacing the original ETag', async () => {
        const fetch = vi.fn().mockResolvedValue(response({}, 'old-0'));
        const data = await remoteConfigRequest(
            'p',
            't',
            { type: 'validate', template },
            fetch
        );
        expect(data).toMatchObject({ etag: 'old' });
        expect(fetch.mock.calls[0]![0]).toContain('?validate_only=true');
    });

    it.each([
        ['INVALID_ARGUMENT', 400, 'invalid-argument'],
        ['PERMISSION_DENIED', 403, 'permission-denied'],
        ['NOT_FOUND', 404, 'not-found'],
        ['ABORTED', 412, 'etag-mismatch'],
        ['UNAUTHENTICATED', 401, 'authentication-error'],
        ['UNAVAILABLE', 503, 'unavailable']
    ])('maps %s errors', async (status, http, code) => {
        const fetch = vi
            .fn()
            .mockResolvedValue(
                response(
                    { error: { status, message: 'failure' } },
                    null,
                    http as number
                )
            );
        await expect(
            remoteConfigRequest('p', 't', { type: 'get' }, fetch)
        ).rejects.toMatchObject({
            code: `remote-config/${code}`,
            message: 'failure'
        });
    });

    it('rejects missing ETags, malformed responses, and non-JSON errors', async () => {
        for (const res of [response({}, null), response([])]) {
            const fetch = vi.fn().mockResolvedValue(res);
            await expect(
                remoteConfigRequest('p', 't', { type: 'get' }, fetch)
            ).rejects.toBeInstanceOf(Error);
        }
        const malformedListFetch = vi
            .fn()
            .mockResolvedValue(response({ versions: {} }));
        await expect(
            remoteConfigRequest('p', 't', { type: 'list' }, malformedListFetch)
        ).rejects.toBeInstanceOf(Error);
        const fetch = vi
            .fn()
            .mockResolvedValue(new Response('unavailable', { status: 500 }));
        await expect(
            remoteConfigRequest('p', 't', { type: 'get' }, fetch)
        ).rejects.toMatchObject({ code: 'remote-config/unknown-error' });
    });

    it('normalizes version lists', async () => {
        const fetch = vi.fn().mockResolvedValue(
            response(
                {
                    versions: [
                        {
                            versionNumber: '3',
                            updateTime: '2025-01-01T00:00:00Z'
                        }
                    ],
                    nextPageToken: 'next'
                },
                null
            )
        );
        const data = await remoteConfigRequest(
            'p',
            't',
            { type: 'list' },
            fetch
        );
        expect(data).toMatchObject({
            versions: [{ updateTime: 'Wed, 01 Jan 2025 00:00:00 GMT' }],
            nextPageToken: 'next'
        });
    });

    it('rejects invalid versions and force without sending a request', async () => {
        const fetch = vi.fn();
        const operations: RemoteConfigOperation[] = [
            ...[
                0,
                -1,
                1.5,
                NaN,
                '',
                '1e2',
                '9223372036854775808',
                Number.MAX_SAFE_INTEGER + 1
            ].map((version) => ({ type: 'rollback' as const, version })),
            { type: 'publish', template, force: 'yes' as never },
            { type: 'publish', template: {} as never }
        ];
        for (const operation of operations) {
            await expect(
                remoteConfigRequest('p', 't', operation, fetch)
            ).rejects.toMatchObject({ code: 'remote-config/invalid-argument' });
        }
        expect(fetch).not.toHaveBeenCalled();
    });
});

describe('remoteConfigListParams', () => {
    it('converts pagination and date filters', () => {
        expect(
            remoteConfigListParams({
                pageSize: 300,
                pageToken: 'next',
                endVersionNumber: 5,
                startTime: new Date('2025-01-01'),
                endTime: '2026-01-01'
            })
        ).toEqual({
            pageSize: '300',
            pageToken: 'next',
            endVersionNumber: '5',
            startTime: '2025-01-01T00:00:00.000Z',
            endTime: '2026-01-01T00:00:00.000Z'
        });
        expect(remoteConfigListParams()).toEqual({});
    });
    it.each([
        null,
        [],
        { pageSize: 0 },
        { pageSize: 301 },
        { pageSize: 1.5 },
        { pageToken: '' },
        { endVersionNumber: -1 },
        { startTime: 'bad' },
        { endTime: 0 },
        { startTime: new Date(NaN) }
    ])('rejects invalid options %j', (options) => {
        expect(() => remoteConfigListParams(options as never)).toThrow();
    });
});
