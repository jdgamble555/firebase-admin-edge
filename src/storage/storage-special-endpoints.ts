import { FirebaseEdgeError } from '../auth/errors.js';

/** @internal Accept Admin topic IDs and resource names while building one canonical Pub/Sub resource. */
export function storageNotificationTopic(
    project: string,
    topic: string
): string {
    if (typeof topic !== 'string' || !topic.trim() || /\s/.test(topic)) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'A Pub/Sub topic is required.'
        });
    }
    const path = topic.replace(/^\/\/pubsub\.googleapis\.com\//, '');
    const resource = path.includes('/')
        ? path
        : `projects/${project}/topics/${path}`;
    if (!/^projects\/[^/]+\/topics\/[^/]+$/.test(resource)) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Invalid Pub/Sub topic resource.'
        });
    }
    return `//pubsub.googleapis.com/${resource}`;
}
import {
    storageFetch,
    readStorageObject,
    validateStorageOperation
} from './storage-endpoints.js';
import { validateIamPolicy } from './storage-bucket-endpoints.js';
import type {
    StorageSpecialOperation,
    StorageSpecialResponses
} from './storage-special-types.js';

/** @internal Validate resource identifiers and specialized request bodies before OAuth. */
export function validateSpecialOperation(
    bucket: string | undefined,
    project: string,
    operation: StorageSpecialOperation
) {
    if (operation.kind.startsWith('hmac')) {
        if (typeof project !== 'string' || !project.trim()) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'HMAC operations require a project ID.'
            });
        }
    } else {
        validateStorageOperation(bucket, { kind: 'list', options: {} });
    }
    for (const key of [
        'id',
        'accessId',
        'entity',
        'serviceAccountEmail'
    ] as const) {
        if (key in operation) {
            const value = (operation as unknown as Record<string, unknown>)[
                key
            ];
            if (
                typeof value !== 'string' ||
                !value.trim() ||
                /[\r\n]/.test(value) ||
                value === '.' ||
                value === '..'
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: `Invalid ${key}.`
                });
            }
        }
    }
    if ('name' in operation) {
        if (
            typeof operation.name !== 'string' ||
            !operation.name.endsWith('/') ||
            operation.name === '/'
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Managed folder names must be nonempty and end in /.'
            });
        }
        validateStorageOperation(bucket, {
            kind: 'metadata',
            name: operation.name
        });
    }
    if ('options' in operation) {
        validateStorageOperation(
            bucket ?? 'validation',
            operation.kind === 'folderList' || operation.kind === 'hmacList'
                ? { kind: 'list', options: operation.options }
                : {
                      kind: 'metadata',
                      name: 'validation',
                      options: operation.options
                  }
        );
        const options = operation.options as Record<string, unknown>;
        for (const key of ['allowNonEmpty', 'showDeletedKeys']) {
            if (
                options[key] !== undefined &&
                typeof options[key] !== 'boolean'
            ) {
                throw new FirebaseEdgeError({
                    code: 'storage/invalid-argument',
                    message: `${key} must be a boolean.`
                });
            }
        }
        if (
            options.serviceAccountEmail !== undefined &&
            (typeof options.serviceAccountEmail !== 'string' ||
                !options.serviceAccountEmail.trim())
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Invalid service account email filter.'
            });
        }
    }
    if (operation.kind === 'notificationCreate') {
        const config = operation.config;
        if (
            !config ||
            typeof config !== 'object' ||
            !/^\/\/pubsub\.googleapis\.com\/projects\/[^/]+\/topics\/[^/]+$/.test(
                config.topic
            ) ||
            !['JSON_API_V1', 'NONE'].includes(config.payload_format) ||
            (config.object_name_prefix !== undefined &&
                typeof config.object_name_prefix !== 'string') ||
            (config.event_types !== undefined &&
                (!Array.isArray(config.event_types) ||
                    config.event_types.some(
                        (event) =>
                            ![
                                'OBJECT_FINALIZE',
                                'OBJECT_METADATA_UPDATE',
                                'OBJECT_DELETE',
                                'OBJECT_ARCHIVE'
                            ].includes(event)
                    ))) ||
            (config.custom_attributes !== undefined &&
                (!config.custom_attributes ||
                    typeof config.custom_attributes !== 'object' ||
                    Array.isArray(config.custom_attributes) ||
                    Object.values(config.custom_attributes).some(
                        (value) => typeof value !== 'string'
                    )))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Invalid notification configuration.'
            });
        }
    }
    if (operation.kind === 'folderSetIam') {
        validateIamPolicy(operation.policy);
    }
    if (
        operation.kind === 'folderTestIam' &&
        (!Array.isArray(operation.permissions) ||
            operation.permissions.length === 0 ||
            operation.permissions.some(
                (permission) =>
                    typeof permission !== 'string' ||
                    !permission.startsWith('storage.') ||
                    permission.includes('*')
            ))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Provide explicit Storage IAM permissions.'
        });
    }
    if (
        operation.kind === 'hmacUpdate' &&
        (!['ACTIVE', 'INACTIVE'].includes(operation.state) ||
            (operation.etag !== undefined &&
                typeof operation.etag !== 'string'))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'HMAC state must be ACTIVE or INACTIVE with an optional etag.'
        });
    }
    if ('target' in operation) {
        const target = operation.target;
        if (
            !target ||
            !['bucket', 'defaultObject', 'object'].includes(target.scope)
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Invalid ACL target.'
            });
        }
        if (target.scope === 'object') {
            validateStorageOperation(bucket, {
                kind: 'metadata',
                name: target.name,
                options: { generation: target.generation }
            });
        }
        if (
            'entry' in operation &&
            (!operation.entry ||
                typeof operation.entry.entity !== 'string' ||
                !operation.entry.entity.trim() ||
                /[\r\n]/.test(operation.entry.entity) ||
                operation.entry.entity === '.' ||
                operation.entry.entity === '..' ||
                ![
                    'OWNER',
                    'READER',
                    ...(target.scope === 'bucket' ? ['WRITER'] : [])
                ].includes(operation.entry.role))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Invalid ACL entity or role.'
            });
        }
    }
}

/** @internal Specialized resources share the same auth and error transport as object requests. */
export async function specialStorageRequest<
    K extends StorageSpecialOperation['kind']
>(
    bucket: string | undefined,
    project: string,
    token: string,
    request: StorageSpecialOperation & { kind: K },
    fetch: typeof globalThis.fetch
): Promise<StorageSpecialResponses[K]> {
    const operation: StorageSpecialOperation = request;
    validateSpecialOperation(bucket, project, operation);
    const { url, method, body } = buildSpecialRequest(
        bucket,
        project,
        operation
    );
    const response = await storageFetch(
        url.toString(),
        {
            method,
            headers: {
                Authorization: `Bearer ${token}`,
                ...(body !== undefined && {
                    'Content-Type': 'application/json'
                })
            },
            ...(body !== undefined && { body: JSON.stringify(body) })
        },
        fetch,
        [],
        'resource-not-found'
    );
    if (operation.kind.endsWith('Delete')) {
        return undefined as unknown as StorageSpecialResponses[K];
    }
    const data = await readStorageObject(response);
    if (
        operation.kind === 'folderGetIam' ||
        operation.kind === 'folderSetIam'
    ) {
        const policy = { ...data, bindings: data.bindings ?? [] };
        try {
            validateIamPolicy(policy);
        } catch {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Invalid managed folder IAM response.'
            });
        }
        return policy as unknown as StorageSpecialResponses[K];
    }
    if (operation.kind === 'folderTestIam') {
        if (
            data.permissions !== undefined &&
            (!Array.isArray(data.permissions) ||
                data.permissions.some((value) => typeof value !== 'string'))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Invalid permission response.'
            });
        }
        return (data.permissions ??
            []) as unknown as StorageSpecialResponses[K];
    }
    if (operation.kind.endsWith('List')) {
        if (
            (data.items !== undefined && !Array.isArray(data.items)) ||
            (data.nextPageToken !== undefined &&
                typeof data.nextPageToken !== 'string')
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Invalid resource list response.'
            });
        }
        return {
            items: (data.items ?? []).map((item) =>
                parseSpecialResource(operation.kind, item)
            ),
            ...(data.nextPageToken !== undefined && {
                nextPageToken: data.nextPageToken
            })
        } as unknown as StorageSpecialResponses[K];
    }
    if (operation.kind === 'hmacCreate') {
        if (typeof data.secret !== 'string' || !data.secret) {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Missing HMAC secret in creation response.'
            });
        }
        const metadata = parseSpecialResource('hmacGet', data.metadata);
        return {
            metadata,
            secret: data.secret
        } as unknown as StorageSpecialResponses[K];
    }
    return parseSpecialResource(
        operation.kind,
        data
    ) as unknown as StorageSpecialResponses[K];
}

/** @internal Build URLs and bodies without exposing transport details in Storage. */
function buildSpecialRequest(
    bucket: string | undefined,
    project: string,
    operation: StorageSpecialOperation
) {
    let path = `/b/${encodeURIComponent(bucket ?? '')}`;
    let body: object | undefined;
    let method = 'GET';
    const params = new URLSearchParams();
    if (operation.kind.startsWith('notification')) {
        path += '/notificationConfigs';
        if ('id' in operation) {
            path += `/${encodeURIComponent(operation.id)}`;
        }
        if (operation.kind === 'notificationCreate') {
            body = operation.config;
            method = 'POST';
        }
    } else if (operation.kind.startsWith('folder')) {
        path += '/managedFolders';
        if ('name' in operation && operation.kind !== 'folderCreate') {
            path += `/${encodeURIComponent(operation.name)}`;
        }
        if (operation.kind === 'folderCreate') {
            body = { name: operation.name };
            method = 'POST';
        }
        if (
            operation.kind === 'folderGetIam' ||
            operation.kind === 'folderSetIam'
        ) {
            path += '/iam';
        }
        if (operation.kind === 'folderGetIam') {
            params.set('optionsRequestedPolicyVersion', '3');
        }
        if (operation.kind === 'folderSetIam') {
            body = operation.policy;
            method = 'PUT';
        }
        if (operation.kind === 'folderTestIam') {
            path += '/iam/testPermissions';
            for (const permission of operation.permissions) {
                params.append('permissions', permission);
            }
        }
    } else if (operation.kind.startsWith('hmac')) {
        path = `/projects/${encodeURIComponent(project)}/hmacKeys`;
        if ('accessId' in operation) {
            path += `/${encodeURIComponent(operation.accessId)}`;
        }
        if (operation.kind === 'hmacCreate') {
            params.set('serviceAccountEmail', operation.serviceAccountEmail);
            method = 'POST';
        }
        if (operation.kind === 'hmacUpdate') {
            body = {
                state: operation.state,
                ...(operation.etag !== undefined && { etag: operation.etag })
            };
            method = 'PUT';
        }
    } else if ('target' in operation) {
        const target = operation.target;
        path +=
            target.scope === 'bucket'
                ? '/acl'
                : target.scope === 'defaultObject'
                  ? '/defaultObjectAcl'
                  : `/o/${encodeURIComponent(target.name)}/acl`;
        if (target.scope === 'object' && target.generation !== undefined) {
            params.set('generation', target.generation);
        }
        if ('entity' in operation) {
            path += `/${encodeURIComponent(operation.entity)}`;
        }
        if ('entry' in operation) {
            body = {
                entity: operation.entry.entity,
                role: operation.entry.role
            };
            method = operation.kind === 'aclCreate' ? 'POST' : 'PATCH';
            if (operation.kind === 'aclUpdate') {
                path += `/${encodeURIComponent(operation.entry.entity)}`;
            }
        }
    }
    if ('options' in operation) {
        for (const key of [
            'pageToken',
            'maxResults',
            'prefix',
            'ifMetagenerationMatch',
            'ifMetagenerationNotMatch',
            'allowNonEmpty',
            'serviceAccountEmail',
            'showDeletedKeys'
        ]) {
            const value = (operation.options as Record<string, unknown>)[key];
            if (value !== undefined) {
                params.set(
                    operation.kind === 'folderList' && key === 'maxResults'
                        ? 'pageSize'
                        : key,
                    String(value)
                );
            }
        }
    }
    if (operation.kind.endsWith('Delete')) {
        method = 'DELETE';
    }
    const url = new URL(`https://storage.googleapis.com/storage/v1${path}`);
    url.search = params.toString();
    return { url, method, body };
}

/** @internal Validate resource identity while preserving the API metadata. */
function parseSpecialResource(
    kind: string,
    value: unknown
): Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new FirebaseEdgeError({
            code: 'storage/internal-error',
            message: 'Invalid Storage resource response.'
        });
    }
    const data = value as Record<string, unknown>;
    const fields = kind.startsWith('notification')
        ? ['id', 'topic', 'payload_format']
        : kind.startsWith('folder')
          ? ['name', 'metageneration']
          : kind.startsWith('hmac')
            ? ['accessId', 'projectId', 'serviceAccountEmail', 'state']
            : ['entity', 'role'];
    if (
        fields.some((field) => typeof data[field] !== 'string' || !data[field])
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/internal-error',
            message: 'Invalid Storage resource metadata.'
        });
    }
    return data;
}
