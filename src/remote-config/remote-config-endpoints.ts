import { FirebaseEdgeError } from '../auth/errors.js';
import { restFetch } from '../rest-fetch.js';
import type {
    ListVersionsOptions,
    RemoteConfigTemplate,
    ServerTemplateData,
    ListVersionsResult
} from './remote-config-types.js';
import {
    invalidRemoteConfig,
    isRemoteConfigObject
} from './remote-config-results.js';
import {
    normalizeTemplate,
    normalizeVersion,
    validateVersionNumber
} from './remote-config-template.js';

export type RemoteConfigOperation =
    | { type: 'get'; version?: string | number }
    | {
          type: 'publish' | 'validate';
          template: RemoteConfigTemplate;
          force?: boolean;
      }
    | { type: 'rollback'; version: string | number }
    | { type: 'list'; options?: ListVersionsOptions }
    | { type: 'server' };

/** @internal Validate list options and convert dates to the REST representation. */
export function remoteConfigListParams(
    options: ListVersionsOptions = {}
): Record<string, string> {
    if (!isRemoteConfigObject(options)) {
        invalidRemoteConfig('List options must be an object.');
    }
    const params: Record<string, string> = {};
    if (options.pageSize !== undefined) {
        if (
            !Number.isInteger(options.pageSize) ||
            options.pageSize < 1 ||
            options.pageSize > 300
        ) {
            invalidRemoteConfig(
                'pageSize must be an integer between 1 and 300.'
            );
        }
        params.pageSize = String(options.pageSize);
    }
    if (options.pageToken !== undefined) {
        if (
            typeof options.pageToken !== 'string' ||
            !options.pageToken.trim()
        ) {
            invalidRemoteConfig('pageToken must be a non-empty string.');
        }
        params.pageToken = options.pageToken;
    }
    if (options.endVersionNumber !== undefined) {
        params.endVersionNumber = validateVersionNumber(
            options.endVersionNumber
        );
    }
    for (const key of ['startTime', 'endTime'] as const) {
        const value = options[key];
        if (value === undefined) {
            continue;
        }
        if (
            !(value instanceof Date) &&
            (typeof value !== 'string' || !value.trim())
        ) {
            invalidRemoteConfig(`${key} must be a date or date string.`);
        }
        const date = new Date(value);
        if (!Number.isFinite(date.getTime())) {
            invalidRemoteConfig(`Invalid ${key}.`);
        }
        params[key] = date.toISOString();
    }
    return params;
}

/** @internal Owns Remote Config URLs, ETags, request bodies, and API errors. */
export async function remoteConfigRequest(
    projectId: string,
    accessToken: string,
    operation: RemoteConfigOperation,
    fetch: typeof globalThis.fetch
): Promise<RemoteConfigTemplate | ServerTemplateData | ListVersionsResult> {
    let path = 'remoteConfig';
    let method: 'GET' | 'POST' | 'PUT' = 'GET';
    let body: object | undefined;
    let params: Record<string, string> | undefined;
    let originalEtag: string | undefined;
    const headers: Record<string, string> = { 'Accept-Encoding': 'gzip' };

    switch (operation.type) {
        case 'get':
            if ('version' in operation) {
                params = {
                    versionNumber: validateVersionNumber(
                        operation.version as string | number
                    )
                };
            }
            break;

        case 'rollback':
            path += ':rollback';
            method = 'POST';
            body = { versionNumber: validateVersionNumber(operation.version) };
            break;

        case 'list':
            path += ':listVersions';
            params = remoteConfigListParams(operation.options);
            break;

        case 'server':
            path = 'namespaces/firebase-server/serverRemoteConfig';
            break;

        case 'publish':
        case 'validate': {
            if (
                operation.force !== undefined &&
                typeof operation.force !== 'boolean'
            ) {
                invalidRemoteConfig('force must be a boolean.');
            }
            const template = normalizeTemplate(operation.template);
            method = 'PUT';
            headers['If-Match'] = operation.force ? '*' : template.etag;
            body = {
                conditions: template.conditions,
                parameters: template.parameters,
                parameterGroups: template.parameterGroups ?? {},
                ...(template.version && {
                    version: { description: template.version.description }
                })
            };
            if (operation.type === 'validate') {
                params = { validate_only: 'true' };
                originalEtag = template.etag;
            }
            break;
        }
    }
    let responseEtag: string | null = null;
    let responseStatus = 0;
    const captureFetch: typeof globalThis.fetch = async (input, init) => {
        const response = await fetch(input, init);
        responseEtag = response.headers.get('etag');
        responseStatus = response.status;
        return response;
    };
    const { error, data } = await restFetch<
        Record<string, unknown>,
        { error?: { status?: string; message?: string } } | string
    >(
        `https://firebaseremoteconfig.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/${path}`,
        {
            method,
            body,
            params,
            headers,
            bearerToken: accessToken,
            global: { fetch: captureFetch }
        }
    );
    if (error !== null) {
        const codes: Record<string, string> = {
            INVALID_ARGUMENT: 'invalid-argument',
            NOT_FOUND: 'not-found',
            PERMISSION_DENIED: 'permission-denied',
            UNAUTHENTICATED: 'authentication-error',
            RESOURCE_EXHAUSTED: 'resource-exhausted',
            FAILED_PRECONDITION: 'failed-precondition',
            ABORTED: 'aborted',
            INTERNAL: 'internal-error',
            UNAVAILABLE: 'unavailable',
            UNKNOWN: 'unknown-error'
        };
        const status =
            typeof error === 'object' ? error?.error?.status : undefined;
        throw new FirebaseEdgeError({
            code: `remote-config/${responseStatus === 412 ? 'etag-mismatch' : (codes[status ?? ''] ?? 'unknown-error')}`,
            message:
                typeof error === 'string'
                    ? error
                    : (error?.error?.message ?? 'Remote Config request failed.')
        });
    }
    if (!isRemoteConfigObject(data)) {
        throw new FirebaseEdgeError({
            code: 'remote-config/internal-error',
            message: 'Invalid Remote Config response.'
        });
    }
    if (operation.type === 'list') {
        if (data.versions !== undefined && !Array.isArray(data.versions)) {
            throw new FirebaseEdgeError({
                code: 'remote-config/internal-error',
                message: 'Invalid version list.'
            });
        }
        return {
            versions: (
                (data.versions ?? []) as ListVersionsResult['versions']
            ).map(normalizeVersion),
            nextPageToken: data.nextPageToken as string | undefined
        };
    }
    if (!responseEtag) {
        throw new FirebaseEdgeError({
            code: 'remote-config/internal-error',
            message: 'Remote Config response is missing its ETag.'
        });
    }
    return { ...data, etag: originalEtag ?? responseEtag } as unknown as
        | RemoteConfigTemplate
        | ServerTemplateData;
}
