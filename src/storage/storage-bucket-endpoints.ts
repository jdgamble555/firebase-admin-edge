import { FirebaseEdgeError } from '../auth/errors.js';
import {
    readStorageObject,
    storageFetch,
    validateStorageOperation
} from './storage-endpoints.js';
import type {
    StorageBucketMetadata,
    StorageBucketOperation,
    StorageBucketResponses,
    StorageIamPolicy
} from './storage-bucket-types.js';

/** @internal Validate administration requests before obtaining credentials. */
export function validateBucketOperation(
    bucket: string | undefined,
    project: string,
    operation: StorageBucketOperation
) {
    if (
        operation.kind === 'lockRetention' &&
        (!operation.options ||
            typeof operation.options.ifMetagenerationMatch !== 'string' ||
            !/^[1-9]\d*$/.test(operation.options.ifMetagenerationMatch))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'Locking retention requires the current positive bucket metageneration.'
        });
    }
    if (operation.kind !== 'list') {
        validateStorageOperation(bucket, { kind: 'list', options: {} });
    }
    if (
        (operation.kind === 'list' || operation.kind === 'create') &&
        (typeof project !== 'string' || !project.trim())
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'A project ID is required for bucket creation and listing.'
        });
    }
    if ('options' in operation) {
        validateStorageOperation(
            bucket ?? 'validation',
            operation.kind === 'list'
                ? { kind: 'list', options: operation.options }
                : {
                      kind: 'metadata',
                      name: 'validation',
                      options: operation.options
                  }
        );
    }
    if (operation.kind === 'create' || operation.kind === 'update') {
        const metadata =
            operation.kind === 'create'
                ? storageBucketCreation(operation.metadata).metadata
                : operation.metadata;
        validateBucketMetadata(metadata, operation.kind === 'create');
    }
    if (operation.kind === 'setIam') {
        validateIamPolicy(operation.policy);
    }
    if (
        operation.kind === 'testIam' &&
        (!Array.isArray(operation.permissions) ||
            operation.permissions.length === 0 ||
            operation.permissions.some(
                (value) =>
                    typeof value !== 'string' ||
                    !value.startsWith('storage.') ||
                    value.includes('*')
            ))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'Provide nonempty Storage IAM permission names without wildcards.'
        });
    }
}

/** @internal Bucket settings and IAM transport. */
export async function bucketRequest<K extends StorageBucketOperation['kind']>(
    bucket: string | undefined,
    project: string,
    token: string,
    request: StorageBucketOperation & { kind: K },
    fetch: typeof globalThis.fetch
): Promise<StorageBucketResponses[K]> {
    const operation: StorageBucketOperation = request;
    if (
        operation.kind === 'getIam' &&
        operation.requestedPolicyVersion !== undefined &&
        ![1, 3].includes(operation.requestedPolicyVersion)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'IAM policy version must be 1 or 3.'
        });
    }
    validateBucketOperation(bucket, project, operation);
    const collection = operation.kind === 'list' || operation.kind === 'create';
    const suffix =
        operation.kind === 'getIam' || operation.kind === 'setIam'
            ? '/iam'
            : operation.kind === 'testIam'
              ? '/iam/testPermissions'
              : operation.kind === 'lockRetention'
                ? '/lockRetentionPolicy'
                : '';
    const url = new URL(
        `https://storage.googleapis.com/storage/v1/b${collection ? '' : `/${encodeURIComponent(bucket!)}`}${suffix}`
    );
    if (collection) {
        url.searchParams.set('project', project);
    }
    if (operation.kind === 'getIam') {
        url.searchParams.set(
            'optionsRequestedPolicyVersion',
            String(operation.requestedPolicyVersion ?? 3)
        );
        if (operation.userProject) {
            url.searchParams.set('userProject', operation.userProject);
        }
    }
    if (operation.kind === 'testIam') {
        for (const permission of operation.permissions) {
            url.searchParams.append('permissions', permission);
        }
    }
    if ('options' in operation) {
        for (const [key, value] of Object.entries(operation.options)) {
            if (
                value !== undefined &&
                [
                    'prefix',
                    'pageToken',
                    'maxResults',
                    'userProject',
                    'generation',
                    'softDeleted',
                    'ifMetagenerationMatch',
                    'ifMetagenerationNotMatch'
                ].includes(key)
            ) {
                url.searchParams.set(key, String(value));
            }
        }
    }
    const creation =
        operation.kind === 'create'
            ? storageBucketCreation(operation.metadata)
            : undefined;
    if (creation) {
        for (const [key, value] of Object.entries(creation.query)) {
            url.searchParams.set(key, String(value));
        }
    }
    const body =
        operation.kind === 'create'
            ? { ...creation!.metadata, name: bucket }
            : operation.kind === 'update'
              ? operation.metadata
              : operation.kind === 'setIam'
                ? operation.policy
                : undefined;
    const response = await storageFetch(
        url.toString(),
        {
            method:
                operation.kind === 'create' ||
                operation.kind === 'lockRetention'
                    ? 'POST'
                    : operation.kind === 'update'
                      ? 'PATCH'
                      : operation.kind === 'delete'
                        ? 'DELETE'
                        : operation.kind === 'setIam'
                          ? 'PUT'
                          : 'GET',
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
        'bucket-not-found'
    );
    if (operation.kind === 'delete') {
        return undefined as StorageBucketResponses[K];
    }
    const data = await readStorageObject(response);
    if (operation.kind === 'getIam' || operation.kind === 'setIam') {
        const policy = { ...data, bindings: data.bindings ?? [] };
        try {
            validateIamPolicy(policy);
        } catch {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Invalid IAM policy response.'
            });
        }
        return policy as StorageBucketResponses[K];
    }
    if (operation.kind === 'testIam') {
        if (
            data.permissions !== undefined &&
            (!Array.isArray(data.permissions) ||
                data.permissions.some((value) => typeof value !== 'string'))
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Invalid IAM permission response.'
            });
        }
        return (data.permissions ?? []) as StorageBucketResponses[K];
    }
    if (operation.kind === 'list') {
        if (
            (data.items !== undefined && !Array.isArray(data.items)) ||
            (data.nextPageToken !== undefined &&
                typeof data.nextPageToken !== 'string')
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/internal-error',
                message: 'Invalid bucket list response.'
            });
        }
        return {
            buckets: (data.items ?? []).map(parseBucketMetadata),
            ...(data.nextPageToken !== undefined && {
                nextPageToken: data.nextPageToken
            })
        } as StorageBucketResponses[K];
    }
    return parseBucketMetadata(data) as StorageBucketResponses[K];
}

/** @internal Preserve the full bucket resource returned by Google. */
function parseBucketMetadata(value: unknown): StorageBucketMetadata {
    if (
        !value ||
        typeof value !== 'object' ||
        !('name' in value) ||
        typeof value.name !== 'string' ||
        !('metageneration' in value) ||
        typeof value.metageneration !== 'string'
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/internal-error',
            message: 'Invalid bucket metadata response.'
        });
    }
    return value as StorageBucketMetadata;
}

/** @internal IAM conditions require policy version 3; preserve etags for concurrency. */
export function validateIamPolicy(
    value: unknown
): asserts value is StorageIamPolicy {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'An IAM policy object is required.'
        });
    }
    const policy = value as StorageIamPolicy;
    if (
        !Array.isArray(policy.bindings) ||
        (policy.version !== undefined &&
            policy.version !== 1 &&
            policy.version !== 3) ||
        (policy.etag !== undefined && typeof policy.etag !== 'string')
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Invalid IAM policy version, etag, or bindings.'
        });
    }
    for (const binding of policy.bindings) {
        if (
            !binding ||
            typeof binding.role !== 'string' ||
            !binding.role ||
            !Array.isArray(binding.members) ||
            binding.members.some(
                (member) => typeof member !== 'string' || !member
            )
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Invalid IAM binding.'
            });
        }
        if (
            binding.condition !== undefined &&
            (!binding.condition ||
                policy.version !== 3 ||
                typeof binding.condition.title !== 'string' ||
                !binding.condition.title ||
                typeof binding.condition.expression !== 'string' ||
                !binding.condition.expression)
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message:
                    'IAM conditions require version 3, a title, and an expression.'
            });
        }
    }
}

/** @internal Reject read-only fields; nested service constraints are also checked by Google. */
function storageBucketCreation(
    options: import('./storage-bucket-types.js').StorageBucketCreateOptions
) {
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Bucket creation options must be an object.'
        });
    }
    const metadata: Record<string, unknown> = { ...options };
    const query: Record<string, string | boolean> = {};
    for (const key of [
        'enableObjectRetention',
        'predefinedAcl',
        'predefinedDefaultObjectAcl',
        'projection',
        'userProject'
    ] as const) {
        const value = options[key];
        delete metadata[key];
        if (value === undefined) {
            continue;
        }
        if (
            key === 'enableObjectRetention'
                ? typeof value !== 'boolean'
                : typeof value !== 'string' || !value.trim()
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: `Invalid bucket creation option: ${key}.`
            });
        }
        if (
            key === 'projection' &&
            !['full', 'noAcl'].includes(value as string)
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Invalid bucket projection.'
            });
        }
        query[key] = value;
    }
    for (const [key, storageClass] of Object.entries({
        standard: 'STANDARD',
        archive: 'ARCHIVE',
        coldline: 'COLDLINE',
        nearline: 'NEARLINE',
        regional: 'REGIONAL',
        multiRegional: 'MULTI_REGIONAL',
        dra: 'DURABLE_REDUCED_AVAILABILITY'
    })) {
        const value = metadata[key];
        delete metadata[key];
        if (value === undefined || value === false) {
            continue;
        }
        if (
            value !== true ||
            (metadata.storageClass !== undefined &&
                metadata.storageClass !== storageClass)
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Conflicting or invalid storage class options.'
            });
        }
        metadata.storageClass = storageClass;
    }
    if (options.dataLocations !== undefined) {
        if (options.customPlacementConfig !== undefined) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message:
                    'Supply dataLocations or customPlacementConfig, not both.'
            });
        }
        metadata.customPlacementConfig = {
            dataLocations: options.dataLocations
        };
    }
    delete metadata.dataLocations;
    if (options.requesterPays !== undefined) {
        if (
            typeof options.requesterPays !== 'boolean' ||
            (options.billing &&
                options.billing.requesterPays !== options.requesterPays)
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'Conflicting or invalid requesterPays options.'
            });
        }
        metadata.billing = { requesterPays: options.requesterPays };
    }
    delete metadata.requesterPays;
    return { metadata, query };
}

function validateBucketMetadata(value: unknown, create: boolean) {
    if (
        !value ||
        typeof value !== 'object' ||
        Array.isArray(value) ||
        Object.keys(value).length === 0
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Nonempty bucket settings are required.'
        });
    }
    const settings = value as Record<string, unknown>;
    if (
        create &&
        (typeof settings.location !== 'string' || !settings.location.trim())
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Bucket creation requires a location.'
        });
    }
    const allowed = [
        'rpo',
        'acl',
        'defaultObjectAcl',
        'logging',
        'website',
        'cors',
        'lifecycle',
        'versioning',
        'labels',
        'storageClass',
        'defaultEventBasedHold',
        'billing',
        'encryption',
        'retentionPolicy',
        'softDeletePolicy',
        'iamConfiguration',
        'autoclass',
        ...(create
            ? ['location', 'customPlacementConfig', 'hierarchicalNamespace']
            : [])
    ];
    for (const [key, item] of Object.entries(settings)) {
        if (!allowed.includes(key) || item === undefined) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: `Invalid writable bucket field: ${key}.`
            });
        }
        if (
            key === 'rpo' &&
            ['DEFAULT', 'ASYNC_TURBO'].includes(item as string)
        ) {
            continue;
        }
        if (
            ['acl', 'defaultObjectAcl'].includes(key) &&
            ((key === 'acl' && item === null) ||
                (Array.isArray(item) &&
                    item.every(
                        (entry) =>
                            entry &&
                            typeof entry.entity === 'string' &&
                            entry.entity.trim() &&
                            ['OWNER', 'READER', 'WRITER'].includes(entry.role)
                    )))
        ) {
            continue;
        }
        if (key === 'location' || key === 'storageClass') {
            if (typeof item === 'string' && item.trim()) {
                continue;
            }
        } else if (key === 'defaultEventBasedHold') {
            if (typeof item === 'boolean') {
                continue;
            }
        } else if (
            item === null &&
            [
                'cors',
                'lifecycle',
                'encryption',
                'retentionPolicy',
                'logging',
                'website'
            ].includes(key)
        ) {
            continue;
        } else if (key === 'cors') {
            if (
                Array.isArray(item) &&
                item.every(
                    (rule) =>
                        rule &&
                        Array.isArray(rule.origin) &&
                        rule.origin.every(
                            (entry: unknown) => typeof entry === 'string'
                        ) &&
                        Array.isArray(rule.method) &&
                        rule.method.every(
                            (entry: unknown) => typeof entry === 'string'
                        ) &&
                        (rule.responseHeader === undefined ||
                            (Array.isArray(rule.responseHeader) &&
                                rule.responseHeader.every(
                                    (entry: unknown) =>
                                        typeof entry === 'string'
                                ))) &&
                        (rule.maxAgeSeconds === undefined ||
                            (Number.isSafeInteger(rule.maxAgeSeconds) &&
                                rule.maxAgeSeconds >= 0))
                )
            ) {
                continue;
            }
        } else if (item && typeof item === 'object' && !Array.isArray(item)) {
            const record = item as Record<string, unknown>;
            if (
                key === 'hierarchicalNamespace' &&
                typeof record.enabled === 'boolean'
            ) {
                continue;
            }
            if (
                key === 'customPlacementConfig' &&
                Array.isArray(record.dataLocations) &&
                record.dataLocations.length === 2 &&
                record.dataLocations.every(
                    (region) => typeof region === 'string' && region.trim()
                ) &&
                new Set(record.dataLocations).size === 2
            ) {
                continue;
            }
            if (
                ['logging', 'website'].includes(key) &&
                Object.values(record).every(
                    (value) => typeof value === 'string'
                )
            ) {
                continue;
            }
            if (
                key === 'labels' &&
                Object.values(record).every(
                    (label) => label === null || typeof label === 'string'
                )
            ) {
                continue;
            }
            if (
                key === 'lifecycle' &&
                Array.isArray(record.rule) &&
                record.rule.every(
                    (rule) =>
                        rule &&
                        rule.action &&
                        [
                            'Delete',
                            'SetStorageClass',
                            'AbortIncompleteMultipartUpload'
                        ].includes(rule.action.type) &&
                        (rule.action.type !== 'SetStorageClass' ||
                            typeof rule.action.storageClass === 'string') &&
                        rule.condition &&
                        typeof rule.condition === 'object' &&
                        !Array.isArray(rule.condition) &&
                        Object.keys(rule.condition).length > 0
                )
            ) {
                continue;
            }
            if (
                ['versioning', 'autoclass'].includes(key) &&
                typeof record.enabled === 'boolean'
            ) {
                continue;
            }
            if (
                key === 'billing' &&
                typeof record.requesterPays === 'boolean'
            ) {
                continue;
            }
            if (
                key === 'encryption' &&
                typeof record.defaultKmsKeyName === 'string'
            ) {
                continue;
            }
            if (
                key === 'retentionPolicy' &&
                ((typeof record.retentionPeriod === 'string' &&
                    /^\d+$/.test(record.retentionPeriod)) ||
                    (Number.isSafeInteger(record.retentionPeriod) &&
                        Number(record.retentionPeriod) >= 0)) &&
                !('isLocked' in record)
            ) {
                continue;
            }
            if (
                key === 'softDeletePolicy' &&
                ((typeof record.retentionDurationSeconds === 'string' &&
                    /^\d+$/.test(record.retentionDurationSeconds)) ||
                    (Number.isSafeInteger(record.retentionDurationSeconds) &&
                        Number(record.retentionDurationSeconds) >= 0))
            ) {
                continue;
            }
            if (
                key === 'iamConfiguration' &&
                (record.publicAccessPrevention === undefined ||
                    ['enforced', 'inherited'].includes(
                        record.publicAccessPrevention as string
                    )) &&
                (record.uniformBucketLevelAccess === undefined ||
                    (record.uniformBucketLevelAccess &&
                        typeof record.uniformBucketLevelAccess === 'object' &&
                        'enabled' in record.uniformBucketLevelAccess &&
                        typeof record.uniformBucketLevelAccess.enabled ===
                            'boolean'))
            ) {
                continue;
            }
        }
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: `Invalid bucket setting: ${key}.`
        });
    }
}
