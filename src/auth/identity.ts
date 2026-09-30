import type {
    IdentityCreateData,
    IdentityImportRecord
} from './identity-write.js';
import type { UserImportRecord, UserImportOptions } from './user-import.js';
export type {
    IdentityCreateData,
    IdentityImportRecord,
    IdentityUpdateData,
    IdentitySetData,
    IdentityWriteResult
} from './identity-write.js';
import type { ProviderIdentifier } from './user-request.js';
import { invalidConfig } from './auth-config.js';
import type {
    AuthConfigResult,
    ListTenantsResult,
    Tenant
} from './auth-config-types.js';
import { IdentityProviders } from './identity-providers.js';
export {
    IdentityProviders,
    type IdentityProvider
} from './identity-providers.js';
import {
    identityLookupIdentifiers,
    identityOrIdentifiers
} from './identity-filter.js';
import {
    FirebaseAdminAuth,
    type FirebaseAdminAuthOptions
} from './firebase-admin-auth.js';
import type { ServiceAccount } from './firebase-types.js';
import { FirebaseEdgeError, ensureError } from './errors.js';
import { executeIdentityQuery } from './identity-query.js';
import { IdentityCountQuery } from './identity-count-query.js';
import { IdentityReference } from './identity-reference.js';
export {
    IdentityReference,
    type IdentityReferenceOptions,
    type IdentityUserRecord
} from './identity-reference.js';
export { IdentityCountQuery } from './identity-count-query.js';
import type {
    IdentityDirection,
    IdentityFilterField,
    IdentityStringFilterField,
    IdentityOrderField,
    IdentityQueryOptions,
    IdentityQueryResult
} from './identity-types.js';
export type {
    IdentityDirection,
    IdentityIdentifier,
    IdentityFilterField,
    IdentityStringFilterField,
    IdentityOrderField,
    IdentityQueryResult,
    IdentityCountResult
} from './identity-types.js';
import type {
    IdentityQueryBuilder,
    IdentityTokenSort
} from './identity-builder-types.js';
export type {
    IdentityQueryBuilder,
    IdentityNativeFilterField
} from './identity-builder-types.js';
export type IdentityOptions = FirebaseAdminAuthOptions;

/** Fluent Firebase Authentication queries with automatic endpoint selection. */
export class Identity<Claims extends object = Record<string, unknown>> {
    private readonly auth: FirebaseAdminAuth;
    readonly providers: IdentityProviders;

    /** Read supported configuration settings for the parent project. */
    readonly config = {
        get: () => this.auth.projectConfigManager().getProjectConfig()
    };

    /** Read all tenants, or build a query for one page. */
    readonly tenants: IdentityTenants;

    constructor(serviceAccount: ServiceAccount, options: IdentityOptions = {}) {
        this.auth = new FirebaseAdminAuth(serviceAccount, options);
        this.providers = new IdentityProviders(this.auth);
        this.tenants = new IdentityTenants(this.auth);
    }

    users<Schema extends object = Claims>(): IdentityQueryBuilder<
        'base',
        false,
        true,
        Schema
    > {
        return new IdentityQuery<Schema>(
            this.auth
        ) as unknown as IdentityQueryBuilder<'base', false, true, Schema>;
    }
}

/** Immutable, token-paginated query for the parent project's tenants. */
export class IdentityTenants {
    constructor(
        private readonly auth: FirebaseAdminAuth,
        private readonly maxResults?: number,
        private readonly token?: string
    ) {}

    limit(value: number): IdentityTenants {
        if (!Number.isInteger(value) || value < 1 || value > 1000) {
            throw invalidConfig('Tenant limit must be between 1 and 1000.');
        }
        return new IdentityTenants(this.auth, value, this.token);
    }

    pageToken(value: string): IdentityTenants {
        if (typeof value !== 'string' || !value.length) {
            throw invalidConfig('pageToken must be a non-empty string.');
        }
        return new IdentityTenants(this.auth, this.maxResults, value);
    }

    async get(): Promise<AuthConfigResult<ListTenantsResult>> {
        const manager = this.auth.tenantManager();
        if (this.maxResults !== undefined || this.token !== undefined) {
            return manager.listTenants(this.maxResults ?? 1000, this.token);
        }

        const tenants: Tenant[] = [];
        const seenTokens = new Set<string>();
        let pageToken: string | undefined;
        do {
            const { error, data } = await manager.listTenants(1000, pageToken);
            if (error) {
                return { error, data: null };
            }
            tenants.push(...data.tenants);
            pageToken = data.pageToken;
            if (pageToken && seenTokens.has(pageToken)) {
                return {
                    data: null,
                    error: new FirebaseEdgeError({
                        code: 'auth/internal-error',
                        message: 'Tenant pagination repeated a page token.'
                    })
                };
            }
            if (pageToken) {
                seenTokens.add(pageToken);
            }
        } while (pageToken);

        return { error: null, data: { tenants } };
    }
}

/** Immutable query. Invalid builder arguments throw before any network request. */
export class IdentityQuery<Claims extends object = Record<string, unknown>> {
    constructor(
        private readonly auth: FirebaseAdminAuth,
        private readonly options: IdentityQueryOptions = {},
        private readonly last = false,
        private readonly token?: string
    ) {}

    /** Append exact-match alternatives to one lookup request. */
    or(
        field: IdentityStringFilterField,
        operator: '==',
        value: string
    ): IdentityQueryBuilder<'or', false, true, Claims>;
    or(
        field: IdentityStringFilterField,
        operator: 'in',
        value: readonly string[]
    ): IdentityQueryBuilder<'or', false, true, Claims>;
    or(
        field: 'provider',
        operator: '==',
        value: ProviderIdentifier
    ): IdentityQueryBuilder<'or', false, true, Claims>;
    or(
        field: 'provider',
        operator: 'in',
        value: readonly ProviderIdentifier[]
    ): IdentityQueryBuilder<'or', false, true, Claims>;
    or(
        field: IdentityFilterField,
        operator: '==' | 'in',
        value:
            | string
            | ProviderIdentifier
            | readonly string[]
            | readonly ProviderIdentifier[]
    ): IdentityQueryBuilder<'or', false, true, Claims> {
        if (
            Object.keys(this.options).some((key) => key !== 'identifiers') ||
            this.last ||
            this.token !== undefined
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'OR clauses cannot be combined with where clauses, sorting, limits, offsets, or page tokens.'
            });
        }
        if (operator !== '==' && operator !== 'in') {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'OR clauses support only == and in.'
            });
        }
        const identifiers = identityLookupIdentifiers(
            field,
            operator === 'in'
                ? (value as readonly (string | ProviderIdentifier)[])
                : [value as string | ProviderIdentifier]
        );
        const validated = identityOrIdentifiers([
            ...(this.options.identifiers ?? []),
            ...identifiers
        ]);
        return new IdentityQuery<Claims>(this.auth, {
            identifiers: validated
        }) as unknown as IdentityQueryBuilder<'or', false, true, Claims>;
    }

    add(data: IdentityCreateData<Claims>) {
        this.assertLookupAllowed();
        return this.auth._writeIdentityUser(undefined, data);
    }

    import(
        records: IdentityImportRecord<Claims>[],
        options?: UserImportOptions
    ) {
        this.assertLookupAllowed();
        if (!Array.isArray(records)) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'Import records must be an array.'
            });
        }
        const users = records.map((record) => {
            if (
                !record ||
                typeof record !== 'object' ||
                Array.isArray(record)
            ) {
                return record as UserImportRecord;
            }
            if ('claims' in record) {
                throw new FirebaseEdgeError({
                    code: 'auth/invalid-argument',
                    message: 'Use customClaims in Identity import records.'
                });
            }
            const { customClaims, ...data } = record;
            return {
                ...data,
                ...(customClaims !== undefined && {
                    customClaims: customClaims === null ? {} : customClaims
                })
            };
        });
        return this.auth.importUsers(users, options);
    }

    delete() {
        if (
            this.options.filter?.field !== 'uid' ||
            this.options.filter.operator !== 'in' ||
            this.options.orderBy ||
            this.options.offset !== undefined ||
            this.options.limit !== undefined ||
            this.last ||
            this.token !== undefined
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'Batch deletion requires only a UID in filter.'
            });
        }
        return this.auth.deleteUsers([...this.options.filter.value]);
    }

    byUid<LookupClaims extends object = Claims>(
        uid: string
    ): IdentityReference<false, true, LookupClaims> {
        this.assertLookupAllowed();
        return new IdentityReference<false, true, LookupClaims>(
            this.auth,
            { uid },
            { uidReference: true }
        );
    }

    byEmail(email: string): IdentityReference<false, false, Claims> {
        this.assertLookupAllowed();
        return new IdentityReference<false, false, Claims>(this.auth, {
            email
        });
    }

    byPhoneNumber(
        phoneNumber: string
    ): IdentityReference<false, false, Claims> {
        this.assertLookupAllowed();
        return new IdentityReference<false, false, Claims>(this.auth, {
            phoneNumber
        });
    }

    byProvider(
        providerId: string,
        providerUid: string
    ): IdentityReference<false, false, Claims> {
        this.assertLookupAllowed();
        return new IdentityReference<false, false, Claims>(this.auth, {
            providerId,
            providerUid
        });
    }

    private assertLookupAllowed(): void {
        if (
            Object.keys(this.options).length > 0 ||
            this.last ||
            this.token !== undefined
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'Exact lookups cannot be combined with filters, sorting, limits, offsets, or page tokens.'
            });
        }
    }

    where(
        field: 'provider',
        operator: 'in',
        value: readonly ProviderIdentifier[]
    ): IdentityQueryBuilder<'lookup', false, true, Claims>;
    where<F extends IdentityStringFilterField>(
        field: F,
        operator: 'in',
        value: readonly string[]
    ): IdentityQueryBuilder<
        F extends 'uid' ? 'uidBatch' : 'lookup',
        false,
        true,
        Claims
    >;
    where<F extends IdentityStringFilterField>(
        field: F,
        operator: '==',
        value: string
    ): IdentityQueryBuilder<
        F extends 'initialEmail' ? 'lookup' : 'filtered',
        false,
        false,
        Claims
    >;
    where(
        field: IdentityFilterField,
        operator: '==' | 'in',
        value: string | readonly string[] | readonly ProviderIdentifier[]
    ):
        | IdentityQueryBuilder<'lookup', false, true, Claims>
        | IdentityQueryBuilder<'filtered', false, false, Claims> {
        if (this.options.filter !== undefined) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'Only one where clause is supported: Firebase ignores additional query expressions instead of applying AND.'
            });
        }
        if (
            this.options.identifiers !== undefined ||
            this.token !== undefined ||
            ((field === 'initialEmail' || operator === 'in') &&
                (Object.keys(this.options).length > 0 || this.last))
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'This filter cannot be combined with existing query options or a page token.'
            });
        }
        if (operator !== '==' && operator !== 'in') {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'Identity queries support only == and in filters.'
            });
        }
        if (
            ![
                'uid',
                'email',
                'phoneNumber',
                'initialEmail',
                'provider'
            ].includes(field) ||
            (field === 'provider' && operator !== 'in') ||
            (operator === '==' &&
                (typeof value !== 'string' || value.length === 0))
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'Specify one supported filter with a string for == or a string array for in.'
            });
        }
        const identifiers =
            operator === 'in'
                ? identityLookupIdentifiers(
                      field,
                      value as readonly (string | ProviderIdentifier)[]
                  )
                : identityLookupIdentifiers(field, [value as string]);
        const filter: NonNullable<IdentityQueryOptions['filter']> =
            field === 'provider'
                ? {
                      field,
                      operator: 'in',
                      value: identifiers as ProviderIdentifier[]
                  }
                : operator === 'in'
                  ? {
                        field,
                        operator,
                        value: [...(value as readonly string[])]
                    }
                  : { field, value: value as string };
        return new IdentityQuery<Claims>(
            this.auth,
            { ...this.options, filter },
            this.last,
            this.token
        ) as unknown as
            | IdentityQueryBuilder<'lookup', false, true, Claims>
            | IdentityQueryBuilder<'filtered', false, false, Claims>;
    }

    orderBy<F extends IdentityOrderField, D extends IdentityDirection = 'asc'>(
        field: F,
        direction: D = 'asc' as D
    ): IdentityQueryBuilder<'query', true, IdentityTokenSort<F, D>, Claims> {
        this.assertNativeQuery();
        if (
            this.token !== undefined &&
            (field !== 'uid' || direction !== 'asc')
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'Page tokens require UID ascending order.'
            });
        }
        if (
            ![
                'uid',
                'displayName',
                'createdAt',
                'lastLoginAt',
                'email'
            ].includes(field) ||
            !['asc', 'desc'].includes(direction) ||
            this.options.orderBy
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'Specify one supported sort field and an asc or desc direction.'
            });
        }
        return new IdentityQuery<Claims>(
            this.auth,
            { ...this.options, orderBy: { field, direction } },
            this.last,
            this.token
        ) as unknown as IdentityQueryBuilder<
            'query',
            true,
            IdentityTokenSort<F, D>,
            Claims
        >;
    }

    offset<N extends number>(
        value: N
    ): IdentityQueryBuilder<
        'query',
        false,
        N extends 0 ? true : false,
        Claims
    > {
        this.assertNativeQuery();
        if (this.token !== undefined && value !== 0) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'Page tokens cannot be combined with a nonzero offset.'
            });
        }
        if (!Number.isSafeInteger(value) || value < 0) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'offset must be a nonnegative safe integer.'
            });
        }
        return new IdentityQuery<Claims>(
            this.auth,
            { ...this.options, offset: value },
            this.last,
            this.token
        ) as unknown as IdentityQueryBuilder<
            'query',
            false,
            N extends 0 ? true : false,
            Claims
        >;
    }

    limit(value: number): IdentityQueryBuilder<'query', false, true, Claims> {
        return this.withLimit(value, false) as unknown as IdentityQueryBuilder<
            'query',
            false,
            true,
            Claims
        >;
    }

    /** Return the last matching users in the query's original order. */
    limitToLast(
        value: number
    ): IdentityQueryBuilder<'query', false, false, Claims> {
        return this.withLimit(value, true) as unknown as IdentityQueryBuilder<
            'query',
            false,
            false,
            Claims
        >;
    }

    private withLimit(value: number, last: boolean): IdentityQuery<Claims> {
        this.assertNativeQuery();
        if (last && this.token !== undefined) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'Page tokens cannot be combined with limitToLast.'
            });
        }
        if (
            !Number.isInteger(value) ||
            value < 1 ||
            value > (last ? 500 : 1000)
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: last
                    ? 'limitToLast must be an integer from 1 through 500.'
                    : 'limit must be an integer from 1 through 1000; query pagination supports at most 500.'
            });
        }
        return new IdentityQuery<Claims>(
            this.auth,
            { ...this.options, limit: value },
            last,
            this.token
        );
    }

    /** Resume a UID-ascending listing using the previous result's opaque token. */
    pageToken(
        token: string
    ): IdentityQueryBuilder<'token', false, true, Claims> {
        this.assertNativeQuery();
        if (
            this.options.filter ||
            this.last ||
            (this.options.offset ?? 0) !== 0 ||
            (this.options.orderBy &&
                (this.options.orderBy.field !== 'uid' ||
                    this.options.orderBy.direction !== 'asc'))
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'Page tokens require an unfiltered UID-ascending listing without offset or limitToLast.'
            });
        }
        if (typeof token !== 'string' || token.length === 0) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'pageToken must be a nonempty string returned by a previous listing.'
            });
        }
        return new IdentityQuery<Claims>(
            this.auth,
            this.options,
            this.last,
            token
        ) as unknown as IdentityQueryBuilder<'token', false, true, Claims>;
    }

    /** Count the matching query with one count-only request. */
    count(): IdentityCountQuery {
        this.assertNativeQuery();
        if (this.token !== undefined) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'Cannot count from a page token.'
            });
        }
        return new IdentityCountQuery(this.auth, this.options, this.token);
    }

    private assertNativeQuery(): void {
        if (
            this.options.identifiers !== undefined ||
            this.options.filter?.field === 'initialEmail' ||
            this.options.filter?.operator === 'in'
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'Lookup filters support only get().'
            });
        }
    }

    /** Execute at most one account-data request; unsupported combinations fail before I/O. */
    async get(): Promise<
        | { data: IdentityQueryResult<Claims>; error: null }
        | { data: null; error: Error }
    > {
        try {
            const { error, data } = await executeIdentityQuery(
                this.auth,
                this.options,
                this.last,
                this.token
            );
            if (error) {
                return { error, data: null };
            }
            return { error: null, data: data as IdentityQueryResult<Claims> };
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }
}
