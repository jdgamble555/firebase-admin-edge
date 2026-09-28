import {
    identityLookupIdentifiers,
    identityOrIdentifiers,
    validateIdentityQueryOptions
} from './identity-filter.js';
import type { FirebaseAdminAuth } from './firebase-admin-auth.js';
import { FirebaseEdgeError } from './errors.js';

import type {
    IdentityQueryOptions,
    IdentityQueryResult
} from './identity-types.js';

/** Execute one backend request, never follow a token or scan for more matches. @internal */
export async function executeIdentityQuery(
    auth: FirebaseAdminAuth,
    options: IdentityQueryOptions,
    last = false,
    pageToken?: string
): Promise<
    { data: IdentityQueryResult; error: null } | { data: null; error: Error }
> {
    validateIdentityQueryOptions(options);
    if (
        typeof last !== 'boolean' ||
        (pageToken !== undefined &&
            (typeof pageToken !== 'string' || pageToken.length === 0))
    ) {
        throw new FirebaseEdgeError({
            code: 'auth/invalid-argument',
            message: 'Use a boolean last flag and a nonempty page token.'
        });
    }
    if (
        options.identifiers !== undefined ||
        options.filter?.field === 'initialEmail' ||
        options.filter?.operator === 'in'
    ) {
        if (
            (options.identifiers !== undefined &&
                options.filter !== undefined) ||
            options.orderBy ||
            options.offset !== undefined ||
            options.limit !== undefined ||
            last ||
            pageToken !== undefined
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'Lookup filters do not support sorting, limits, offsets, or page tokens.'
            });
        }
        const identifiers =
            options.identifiers !== undefined
                ? identityOrIdentifiers(options.identifiers)
                : identityLookupIdentifiers(
                      options.filter!.field,
                      options.filter!.operator === 'in'
                          ? options.filter!.value
                          : [options.filter!.value as string]
                  );
        const { error, data } = await auth.getUsers(identifiers);
        if (error) {
            return { error, data: null };
        }
        return {
            error: null,
            data: { users: data.users, nextOffset: null, nextPageToken: null }
        };
    }

    const offset = options.offset ?? 0;
    const limit = options.limit ?? 500;
    const orderBy = options.orderBy ?? { field: 'uid', direction: 'asc' };

    const useBatch =
        !options.filter &&
        !last &&
        offset === 0 &&
        orderBy.field === 'uid' &&
        orderBy.direction === 'asc';

    if (pageToken !== undefined && !useBatch) {
        throw new FirebaseEdgeError({
            code: 'auth/invalid-argument',
            message:
                'Page tokens require an unfiltered UID-ascending listing without offset or limitToLast.'
        });
    }
    if (limit > (useBatch ? 1000 : 500)) {
        throw new FirebaseEdgeError({
            code: 'auth/invalid-argument',
            message: useBatch
                ? 'Token listings support at most 1000 users per request.'
                : 'Filtered, sorted, and offset queries support at most 500 users per request.'
        });
    }
    if (last && offset + limit > 500) {
        throw new FirebaseEdgeError({
            code: 'auth/invalid-argument',
            message:
                'limitToLast plus offset must not exceed 500 for a single query request.'
        });
    }

    if (useBatch) {
        const { error, data } = await auth.listUsers(limit, pageToken);
        if (error) {
            return { data: null, error };
        }
        return {
            data: {
                users: data.users,
                nextOffset: null,
                nextPageToken: data.pageToken ?? null
            },
            error: null
        };
    }

    const request = last
        ? {
              ...options,
              offset: 0,
              limit: limit + offset,
              orderBy: {
                  field: orderBy.field,
                  direction:
                      orderBy.direction === 'asc'
                          ? ('desc' as const)
                          : ('asc' as const)
              }
          }
        : { ...options, orderBy };
    const { error, data } = await auth._queryUsers(request);
    if (error) {
        return { data: null, error };
    }
    if (last) {
        const count = Math.min(limit, Math.max(0, data.length - offset));
        return {
            data: {
                users: data.slice(0, count).reverse(),
                nextOffset: null,
                nextPageToken: null
            },
            error: null
        };
    }
    return {
        data: {
            users: data,
            nextOffset: data.length === limit ? offset + data.length : null,
            nextPageToken: null
        },
        error: null
    };
}
