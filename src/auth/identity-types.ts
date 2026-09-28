import type { ProviderIdentifier, UserIdentifier } from './user-request.js';
import type { IdentityUserRecord } from './identity-reference.js';

export type IdentityFilterField = IdentityStringFilterField | 'provider';
export type IdentityStringFilterField =
    | 'uid'
    | 'email'
    | 'phoneNumber'
    | 'initialEmail';
export type IdentityOrderField =
    | 'uid'
    | 'displayName'
    | 'createdAt'
    | 'lastLoginAt'
    | 'email';
export type IdentityDirection = 'asc' | 'desc';

/** One exact identity, never an implicit conjunction of several identifiers. */
export type IdentityIdentifier =
    | {
          [K in IdentityStringFilterField]: Record<K, string> &
              Partial<
                  Record<
                      | Exclude<IdentityStringFilterField, K>
                      | 'providerId'
                      | 'providerUid',
                      never
                  >
              >;
      }[IdentityStringFilterField]
    | (ProviderIdentifier & Partial<Record<IdentityStringFilterField, never>>);

/** @internal Validated options passed from the fluent query to the endpoint. */
export interface IdentityQueryOptions {
    identifiers?: readonly UserIdentifier[];
    filter?:
        | { field: IdentityStringFilterField; operator?: '=='; value: string }
        | {
              field: IdentityStringFilterField;
              operator: 'in';
              value: readonly string[];
          }
        | {
              field: 'provider';
              operator: 'in';
              value: readonly ProviderIdentifier[];
          };
    orderBy?: { field: IdentityOrderField; direction: IdentityDirection };
    offset?: number;
    limit?: number;
}

export interface IdentityCountResult {
    count: number;
}

export interface IdentityQueryResult<
    Claims extends object = Record<string, unknown>
> {
    users: IdentityUserRecord<Claims>[];
    /** Continuation hint for offset queries; null for listings and limitToLast. */
    nextOffset: number | null;
    /** Opaque continuation token for UID-ascending listings; otherwise null. */
    nextPageToken: string | null;
}
