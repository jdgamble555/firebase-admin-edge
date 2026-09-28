import { FirebaseEdgeError } from './errors.js';
import type {
    IdentityFilterField,
    IdentityQueryOptions
} from './identity-types.js';
import {
    buildUsersLookupRequest,
    type ProviderIdentifier,
    type UserIdentifier
} from './user-request.js';

/** Validate direct query construction as well as fluent queries before I/O. @internal */
export function validateIdentityQueryOptions(
    options: IdentityQueryOptions
): void {
    if (
        !options ||
        typeof options !== 'object' ||
        Array.isArray(options) ||
        Object.keys(options).some(
            (key) =>
                ![
                    'filter',
                    'identifiers',
                    'orderBy',
                    'offset',
                    'limit'
                ].includes(key)
        )
    ) {
        throw new FirebaseEdgeError({
            code: 'auth/invalid-argument',
            message: 'Unsupported identity query options.'
        });
    }
    const { filter, orderBy, offset, limit } = options;
    if (filter !== undefined) {
        if (
            !filter ||
            typeof filter !== 'object' ||
            Array.isArray(filter) ||
            Object.keys(filter).some(
                (key) => !['field', 'operator', 'value'].includes(key)
            ) ||
            (filter.operator !== undefined &&
                filter.operator !== '==' &&
                filter.operator !== 'in') ||
            (filter.field === 'provider' && filter.operator !== 'in')
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'Specify one supported identity filter.'
            });
        }
        identityLookupIdentifiers(
            filter.field,
            filter.operator === 'in' ? filter.value : [filter.value]
        );
    }
    if (options.identifiers !== undefined) {
        identityOrIdentifiers(options.identifiers);
        if (filter !== undefined) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'OR lookups cannot be combined with another filter.'
            });
        }
    }
    if (
        orderBy !== undefined &&
        (!orderBy ||
            typeof orderBy !== 'object' ||
            Array.isArray(orderBy) ||
            Object.keys(orderBy).some(
                (key) => !['field', 'direction'].includes(key)
            ) ||
            ![
                'uid',
                'email',
                'displayName',
                'createdAt',
                'lastLoginAt'
            ].includes(orderBy.field) ||
            !['asc', 'desc'].includes(orderBy.direction))
    ) {
        throw new FirebaseEdgeError({
            code: 'auth/invalid-argument',
            message: 'Specify one supported sort field and direction.'
        });
    }
    if (offset !== undefined && (!Number.isSafeInteger(offset) || offset < 0)) {
        throw new FirebaseEdgeError({
            code: 'auth/invalid-argument',
            message: 'offset must be a nonnegative safe integer.'
        });
    }
    if (
        limit !== undefined &&
        (!Number.isInteger(limit) || limit < 1 || limit > 1000)
    ) {
        throw new FirebaseEdgeError({
            code: 'auth/invalid-argument',
            message: 'limit must be an integer from 1 through 1000.'
        });
    }
}

/** Validate and snapshot an OR of exact identifiers. @internal */
export function identityOrIdentifiers(
    identifiers: readonly UserIdentifier[]
): UserIdentifier[] {
    if (!Array.isArray(identifiers) || identifiers.length === 0) {
        throw new FirebaseEdgeError({
            code: 'auth/invalid-argument',
            message: 'OR requires 1 through 100 exact identifiers.'
        });
    }
    for (const identifier of identifiers) {
        const keys = Object.keys(identifier ?? {});
        const provider =
            keys.includes('providerId') && keys.includes('providerUid');
        if (keys.length !== (provider ? 2 : 1)) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'Each OR branch must contain one identifier or one provider ID/UID pair; AND conditions are unsupported.'
            });
        }
    }
    const { error } = buildUsersLookupRequest([...identifiers]);
    if (error) {
        throw error;
    }
    return identifiers.map((identifier) => ({ ...identifier }));
}

/** Validate one lookup batch without splitting it into multiple requests. @internal */
export function identityLookupIdentifiers(
    field: IdentityFilterField,
    values: readonly (string | ProviderIdentifier)[]
): UserIdentifier[] {
    if (
        !['uid', 'email', 'phoneNumber', 'initialEmail', 'provider'].includes(
            field
        ) ||
        !Array.isArray(values) ||
        values.length === 0 ||
        values.length > 100
    ) {
        throw new FirebaseEdgeError({
            code: 'auth/invalid-argument',
            message:
                'Lookup filters require a supported field and 1 through 100 identifiers.'
        });
    }
    const identifiers = Array.from(values, (value) => {
        if (field === 'provider') {
            const pair = value as ProviderIdentifier | null;
            return {
                providerId: pair?.providerId,
                providerUid: pair?.providerUid
            } as ProviderIdentifier;
        }
        return { [field]: value } as UserIdentifier;
    });
    const { error } = buildUsersLookupRequest(identifiers);
    if (error) {
        throw error;
    }
    return identifiers;
}
