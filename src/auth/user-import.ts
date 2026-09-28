import { base64url } from 'jose';
import {
    FirebaseEdgeError,
    FirebaseAdminAuthErrorInfo,
    ensureError
} from './errors.js';
import {
    buildUserRequest,
    buildCustomClaimsRequest,
    validateUserUid,
    type CreateRequest,
    type UpdateRequest,
    type UserProvider
} from './user-request.js';
import type { FirebaseArrayIndexError } from './user-batch.js';

export type HashAlgorithmType =
    | 'SCRYPT'
    | 'STANDARD_SCRYPT'
    | 'HMAC_SHA512'
    | 'HMAC_SHA256'
    | 'HMAC_SHA1'
    | 'HMAC_MD5'
    | 'MD5'
    | 'PBKDF_SHA1'
    | 'BCRYPT'
    | 'PBKDF2_SHA256'
    | 'SHA512'
    | 'SHA256'
    | 'SHA1';
export interface UserImportOptions {
    /** Overwrite existing accounts with matching UIDs rather than rejecting them. */
    allowOverwrite?: boolean;
    /** Check duplicate emails, duplicate federated IDs, and provider validity. */
    sanityCheck?: boolean;
    hash?: {
        algorithm: HashAlgorithmType;
        key?: Uint8Array;
        saltSeparator?: Uint8Array;
        rounds?: number;
        memoryCost?: number;
        parallelization?: number;
        blockSize?: number;
        derivedKeyLength?: number;
    };
}
export interface UserMetadataRequest {
    creationTime?: string;
    lastSignInTime?: string;
}
export interface UserProviderRequest extends UserProvider {
    uid: string;
    providerId: string;
}
export interface UserImportRecord
    extends Omit<CreateRequest, 'password' | 'multiFactor'> {
    uid: string;
    metadata?: UserMetadataRequest;
    providerData?: UserProviderRequest[];
    customClaims?: Record<string, unknown>;
    passwordHash?: Uint8Array;
    passwordSalt?: Uint8Array;
    tenantId?: string;
    multiFactor?: UpdateRequest['multiFactor'];
}
export interface PreparedUserImport {
    body: { users: Record<string, unknown>[]; [key: string]: unknown };
    indices: number[];
    errors: FirebaseArrayIndexError[];
}

/** Validate writable user metadata and translate timestamps to milliseconds. @internal */
export function buildUserMetadata(
    metadata: UserMetadataRequest
): Record<string, number> {
    if (
        !metadata ||
        typeof metadata !== 'object' ||
        Array.isArray(metadata) ||
        Object.keys(metadata).some(
            (key) => !['creationTime', 'lastSignInTime'].includes(key)
        )
    ) {
        throw new Error(
            'metadata accepts only creationTime and lastSignInTime.'
        );
    }
    const body: Record<string, number> = {};
    for (const [field, target] of [
        ['creationTime', 'createdAt'],
        ['lastSignInTime', 'lastLoginAt']
    ] as const) {
        const value = metadata[field];
        if (value === undefined) {
            continue;
        }
        if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
            throw new Error(`Invalid metadata.${field}.`);
        }
        body[target] = Date.parse(value);
    }
    return body;
}

/** Encode byte buffers with the API's URL-safe base64 alphabet (including padding). */
function encodeBytes(value: Uint8Array): string {
    if (!(value instanceof Uint8Array))
        throw new Error(
            'Password and hash values must be Uint8Array byte buffers.'
        );
    const encoded = base64url.encode(value);
    return encoded.padEnd(Math.ceil(encoded.length / 4) * 4, '=');
}

/** Translate the supported Firebase Admin hash options without hashing on the edge. */
export function buildImportHashOptions(
    options?: UserImportOptions
): Record<string, unknown> {
    if (!options?.hash || typeof options.hash !== 'object')
        throw new Error(
            'Hash options are required when importing password hashes.'
        );
    const hash = options.hash;
    const algorithm = hash.algorithm;
    if (algorithm === 'BCRYPT') return { hashAlgorithm: algorithm };
    if (
        ['HMAC_SHA512', 'HMAC_SHA256', 'HMAC_SHA1', 'HMAC_MD5'].includes(
            algorithm
        )
    ) {
        return { hashAlgorithm: algorithm, signerKey: encodeBytes(hash.key!) };
    }
    if (algorithm === 'STANDARD_SCRYPT') {
        for (const field of [
            'memoryCost',
            'parallelization',
            'blockSize',
            'derivedKeyLength'
        ] as const) {
            if (!Number.isInteger(hash[field]) || hash[field]! <= 0)
                throw new Error(`hash.${field} must be a positive integer.`);
        }
        return {
            hashAlgorithm: algorithm,
            cpuMemCost: hash.memoryCost,
            parallelization: hash.parallelization,
            blockSize: hash.blockSize,
            dkLen: hash.derivedKeyLength
        };
    }
    if (algorithm === 'SCRYPT') {
        if (
            !Number.isInteger(hash.rounds) ||
            hash.rounds! < 1 ||
            hash.rounds! > 8
        )
            throw new Error('SCRYPT rounds must be from 1 to 8.');
        if (
            !Number.isInteger(hash.memoryCost) ||
            hash.memoryCost! < 1 ||
            hash.memoryCost! > 14
        )
            throw new Error('SCRYPT memoryCost must be from 1 to 14.');
        return {
            hashAlgorithm: algorithm,
            signerKey: encodeBytes(hash.key!),
            saltSeparator: encodeBytes(hash.saltSeparator ?? new Uint8Array()),
            rounds: hash.rounds,
            memoryCost: hash.memoryCost
        };
    }
    const isPbkdf = algorithm === 'PBKDF_SHA1' || algorithm === 'PBKDF2_SHA256';
    if (!isPbkdf && !['MD5', 'SHA1', 'SHA256', 'SHA512'].includes(algorithm))
        throw new Error('Unsupported hash algorithm.');
    const min = isPbkdf || algorithm === 'MD5' ? 0 : 1;
    const max = isPbkdf ? 120000 : 8192;
    if (
        !Number.isInteger(hash.rounds) ||
        hash.rounds! < min ||
        hash.rounds! > max
    )
        throw new Error(`Hash rounds must be from ${min} to ${max}.`);
    return { hashAlgorithm: algorithm, rounds: hash.rounds };
}

/** Convert one imported record, reusing the existing profile and MFA validation. */
export function buildImportUser(
    user: UserImportRecord,
    tenantId?: string
): Record<string, unknown> {
    if (!user || typeof user !== 'object' || Array.isArray(user))
        throw new Error('An imported user must be an object.');
    const uidError = validateUserUid(user.uid);
    if (uidError) throw uidError;
    if (
        user.tenantId !== undefined &&
        (typeof user.tenantId !== 'string' ||
            !user.tenantId ||
            (tenantId !== undefined && user.tenantId !== tenantId))
    )
        throw new Error('Invalid or mismatched import tenantId.');
    const base = buildUserRequest(
        {
            email: user.email,
            emailVerified: user.emailVerified,
            displayName: user.displayName,
            photoURL: user.photoURL,
            phoneNumber: user.phoneNumber,
            disabled: user.disabled
        },
        'create'
    );
    if (base.error) throw base.error;
    const body: Record<string, unknown> = { ...base.data, localId: user.uid };
    if (user.tenantId !== undefined) body.tenantId = user.tenantId;
    if (user.passwordHash !== undefined)
        body.passwordHash = encodeBytes(user.passwordHash);
    if (user.passwordSalt !== undefined)
        body.salt = encodeBytes(user.passwordSalt);
    if (user.metadata !== undefined) {
        Object.assign(body, buildUserMetadata(user.metadata));
    }
    if (user.customClaims !== undefined) {
        if (
            !user.customClaims ||
            typeof user.customClaims !== 'object' ||
            Array.isArray(user.customClaims)
        )
            throw new Error('customClaims must be an object.');
        const claims = buildCustomClaimsRequest(user.customClaims);
        if (claims.error) throw claims.error;
        body.customAttributes = claims.data.customAttributes;
    }
    if (user.providerData !== undefined) {
        if (!Array.isArray(user.providerData))
            throw new Error('providerData must be an array.');
        const providers = user.providerData.map((provider) => {
            const converted = buildUserRequest(
                { providerToLink: provider },
                'update'
            );
            if (converted.error) throw converted.error;
            if (!provider || !converted.data.linkProviderUserInfo)
                throw new Error('Invalid provider record.');
            const profile = buildUserRequest(
                {
                    email: provider.email,
                    displayName: provider.displayName,
                    photoURL: provider.photoURL,
                    phoneNumber: provider.phoneNumber
                },
                'create'
            );
            if (profile.error) throw profile.error;
            return {
                ...profile.data,
                rawId: provider.uid,
                providerId: provider.providerId
            };
        });
        if (providers.length) body.providerUserInfo = providers;
    }
    if (user.multiFactor !== undefined) {
        const converted = buildUserRequest(
            { multiFactor: user.multiFactor },
            'update'
        );
        if (converted.error) throw converted.error;
        const mfa = converted.data.mfa as { enrollments?: unknown[] };
        if (mfa.enrollments?.length) body.mfaInfo = mfa.enrollments;
    }
    return body;
}

/** Prepare valid records while collecting per-user errors and preserving original indices. */
export function prepareUserImport(
    users: UserImportRecord[],
    options?: UserImportOptions,
    tenantId?: string
):
    | { data: PreparedUserImport; error: null }
    | { data: null; error: FirebaseEdgeError } {
    if (!Array.isArray(users) || users.length > 1000) {
        return {
            data: null,
            error: new FirebaseEdgeError({
                ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                message: 'users must be an array of at most 1000 records.'
            })
        };
    }
    const flags: Record<string, boolean> = {};
    for (const field of ['allowOverwrite', 'sanityCheck'] as const) {
        const value = options?.[field];
        if (value === undefined) {
            continue;
        }
        if (typeof value !== 'boolean') {
            return {
                data: null,
                error: new FirebaseEdgeError({
                    ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                    message: `${field} must be a boolean.`
                })
            };
        }
        flags[field] = value;
    }
    const records: Record<string, unknown>[] = [];
    const indices: number[] = [];
    const errors: FirebaseArrayIndexError[] = [];
    for (let index = 0; index < users.length; index++) {
        try {
            const record = buildImportUser(users[index]!, tenantId);
            records.push(record);
            indices.push(index);
        } catch (cause) {
            errors.push({
                index,
                error:
                    cause instanceof FirebaseEdgeError
                        ? cause
                        : new FirebaseEdgeError(
                              {
                                  code: 'auth/admin-invalid-user-import',
                                  message: ensureError(cause).message
                              },
                              { cause: ensureError(cause) }
                          )
            });
        }
    }
    try {
        const hashOptions = records.some(
            (user) => user.passwordHash !== undefined
        )
            ? buildImportHashOptions(options)
            : {};
        return {
            data: {
                body: {
                    users: records,
                    ...hashOptions,
                    ...flags
                },
                indices,
                errors
            },
            error: null
        };
    } catch (cause) {
        return {
            data: null,
            error: new FirebaseEdgeError(
                {
                    ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                    message: ensureError(cause).message
                },
                { cause: ensureError(cause) }
            )
        };
    }
}
