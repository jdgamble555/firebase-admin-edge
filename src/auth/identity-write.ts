import {
    buildUserMetadata,
    type UserImportRecord,
    type UserMetadataRequest
} from './user-import.js';
import {
    buildUserRequest,
    buildCustomClaimsRequest,
    type CreateRequest,
    type UpdateRequest
} from './user-request.js';
import { FirebaseEdgeError, ensureError } from './errors.js';

export type IdentityImportRecord<
    Claims extends object = Record<string, unknown>
> = Omit<UserImportRecord, 'customClaims'> & {
    customClaims?: Partial<Claims> | null;
};
export type IdentityCreateData<
    Claims extends object = Record<string, unknown>
> = CreateRequest & {
    customClaims?: Partial<Claims> | null;
};
export type IdentityUpdateData<
    Claims extends object = Record<string, unknown>
> = Omit<UpdateRequest, 'password'> & {
    password?: string | null;
    customClaims?: Partial<Claims> | null;
    metadata?: UserMetadataRequest;
};
export type IdentitySetData<Claims extends object = Record<string, unknown>> =
    Pick<
        IdentityUpdateData<Claims>,
        | 'displayName'
        | 'photoURL'
        | 'phoneNumber'
        | 'disabled'
        | 'emailVerified'
        | 'customClaims'
    > & {
        email?: string | null;
        metadata?: {
            creationTime?: string | null;
            lastSignInTime?: string | null;
        } | null;
    };
export interface IdentityWriteResult {
    uid: string;
}

/** Validate identity writes and combine supported fields in one request. @internal */
export function buildIdentityWriteRequest(
    data: IdentityCreateData | IdentityUpdateData | IdentitySetData,
    operation: 'create' | 'update' | 'set'
) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
        return {
            data: null,
            error: new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'User properties must be an object.'
            })
        };
    }
    const allowed = new Set([
        'email',
        'emailVerified',
        'displayName',
        'photoURL',
        'phoneNumber',
        'disabled',
        ...(operation === 'set'
            ? ['customClaims', 'metadata']
            : [
                  'password',
                  'multiFactor',
                  ...(operation === 'create'
                      ? ['uid', 'customClaims']
                      : [
                            'providerToLink',
                            'providersToUnlink',
                            'customClaims',
                            'metadata'
                        ])
              ])
    ]);
    if (Object.keys(data).some((key) => !allowed.has(key))) {
        return {
            data: null,
            error: new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'Unsupported identity write field.'
            })
        };
    }
    if (
        operation === 'set' &&
        data.email == null &&
        data.emailVerified === true
    ) {
        return {
            data: null,
            error: new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'A verified email requires an email in the replacement.'
            })
        };
    }
    const properties =
        operation === 'set'
            ? {
                  email: data.email ?? undefined,
                  displayName: data.displayName ?? null,
                  photoURL: data.photoURL ?? null,
                  phoneNumber: data.phoneNumber ?? null,
                  disabled: data.disabled === undefined ? false : data.disabled,
                  emailVerified:
                      data.emailVerified === undefined
                          ? false
                          : data.emailVerified
              }
            : operation === 'update'
              ? {
                    ...(data as IdentityUpdateData),
                    password: (data as IdentityUpdateData).password ?? undefined
                }
              : (data as IdentityCreateData);
    const { error, data: body } = buildUserRequest(
        properties,
        operation === 'create' ? 'create' : 'update'
    );
    if (error) {
        return { error, data: null };
    }
    if (operation === 'update') {
        const update = data as IdentityUpdateData;
        if (update.password === null) {
            body.deleteAttribute = [
                ...(body.deleteAttribute ?? []),
                'PASSWORD'
            ];
        }
        if (update.metadata !== undefined) {
            const { error: metadataError, data: metadataBody } =
                buildIdentityMetadataRequest(update.metadata);
            if (metadataError) {
                return { error: metadataError, data: null };
            }
            Object.assign(body, metadataBody);
        }
    }
    if (operation === 'set' && data.email == null) {
        body.deleteAttribute = [...(body.deleteAttribute ?? []), 'EMAIL'];
    }
    if (operation === 'set') {
        const { error: metadataError, data: metadataBody } =
            buildIdentityMetadataRequest(
                (data as IdentitySetData).metadata ?? null,
                true
            );
        if (metadataError) {
            return { error: metadataError, data: null };
        }
        Object.assign(body, metadataBody);
    }
    const { customClaims } = data;
    if (operation === 'set' || customClaims !== undefined) {
        const { error: claimsError, data: claimsBody } =
            buildCustomClaimsRequest(customClaims ?? null);
        if (claimsError) {
            return { error: claimsError, data: null };
        }
        Object.assign(body, claimsBody);
    }
    return { error: null, data: body };
}

/** Validate and serialize metadata for a dedicated UID update. @internal */
export function buildIdentityMetadataRequest(
    metadata: UserMetadataRequest | IdentitySetData['metadata'],
    reset = false
) {
    try {
        if (
            reset &&
            metadata != null &&
            (typeof metadata !== 'object' || Array.isArray(metadata))
        ) {
            throw new Error('metadata must be an object or null.');
        }
        const properties = reset
            ? {
                  ...metadata,
                  creationTime:
                      metadata?.creationTime ?? '1970-01-01T00:00:00.000Z',
                  lastSignInTime:
                      metadata?.lastSignInTime ?? '1970-01-01T00:00:00.000Z'
              }
            : metadata;
        const timestamps = buildUserMetadata(properties as UserMetadataRequest);
        const body: Record<string, string> = {};
        for (const [field, value] of Object.entries(timestamps)) {
            body[field] = String(value);
        }
        return { error: null, data: body };
    } catch (cause) {
        return {
            data: null,
            error: new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: ensureError(cause).message
            })
        };
    }
}
