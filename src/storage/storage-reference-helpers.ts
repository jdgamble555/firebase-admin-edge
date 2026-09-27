import { FirebaseEdgeError } from '../auth/errors.js';
import type {
    PreconditionOptions,
    CopyOptions
} from './storage-reference-types.js';
import type {
    StoragePreconditions,
    StorageCopyOptions
} from './storage-types.js';
import type { StorageIamPolicy } from './storage-bucket-types.js';

/** @internal Normalize Admin numeric preconditions while preserving large string generations. */
export function storagePreconditions(
    options: PreconditionOptions = {}
): StoragePreconditions {
    const result: StoragePreconditions = {
        ...(options.userProject !== undefined && {
            userProject: options.userProject
        })
    };
    for (const key of [
        'ifGenerationMatch',
        'ifGenerationNotMatch',
        'ifMetagenerationMatch',
        'ifMetagenerationNotMatch'
    ] as const) {
        const value = options[key];
        if (value === undefined) {
            continue;
        }
        result[key] = storageGeneration(value);
    }
    return result;
}

/** @internal Reject unsafe numeric generations instead of silently losing precision. */
export function storageGeneration(value: string | number): string {
    if (
        (typeof value === 'number' &&
            (!Number.isSafeInteger(value) || value < 0)) ||
        !/^\d+$/.test(String(value))
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message:
                'Generation values must be nonnegative safe integers or integer strings.'
        });
    }
    return String(value);
}

/** @internal Admin copy metadata fields live at the top level of CopyOptions. */
export function storageCopyOptions(options: CopyOptions): StorageCopyOptions {
    const {
        preconditionOpts,
        contentType,
        cacheControl,
        contentDisposition,
        contentEncoding,
        contentLanguage,
        storageClass,
        temporaryHold,
        eventBasedHold,
        customTime,
        metadata,
        ...copy
    } = options;
    const writable = Object.fromEntries(
        Object.entries({
            contentType,
            cacheControl,
            contentDisposition,
            contentEncoding,
            contentLanguage,
            storageClass,
            temporaryHold,
            eventBasedHold,
            customTime,
            metadata
        }).filter(([, value]) => value !== undefined)
    );
    return {
        ...copy,
        ...storagePreconditions(preconditionOpts),
        ...(Object.keys(writable).length > 0 && { metadata: writable })
    };
}

/** @internal Preserve IAM conditions and etags while granting only log delivery. */
export function storageLoggingPolicy(
    policy: StorageIamPolicy
): StorageIamPolicy | undefined {
    const member = 'group:cloud-storage-analytics@google.com';
    const role = 'roles/storage.objectCreator';
    const binding = policy.bindings.find(
        (entry) => entry.role === role && !entry.condition
    );
    if (binding?.members.includes(member)) {
        return;
    }
    const bindings = policy.bindings.map((entry) =>
        entry === binding
            ? { ...entry, members: [...entry.members, member] }
            : entry
    );
    if (!binding) {
        bindings.push({ role, members: [member] });
    }
    return { ...policy, bindings };
}
