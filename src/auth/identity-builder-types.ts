import type { ProviderIdentifier } from './user-request.js';
import type { IdentityQuery } from './identity.js';
import type { IdentityCountQuery } from './identity-count-query.js';
import type { IdentityReference } from './identity-reference.js';
import type {
    IdentityDirection,
    IdentityStringFilterField,
    IdentityOrderField
} from './identity-types.js';

type Mode =
    | 'base'
    | 'query'
    | 'filtered'
    | 'lookup'
    | 'token'
    | 'uidBatch'
    | 'or';
type Modified<M extends Mode> = M extends 'base' ? 'query' : M;
export type IdentityNativeFilterField = Exclude<
    IdentityStringFilterField,
    'initialEmail'
>;
export type IdentityTokenSort<F, D> = [F] extends ['uid']
    ? [D] extends ['asc']
        ? true
        : false
    : false;

/** A view of the immutable builder exposing only operations its endpoint supports. */
export type IdentityQueryBuilder<
    M extends Mode = 'base',
    Sorted extends boolean = false,
    TokenAllowed extends boolean = true,
    Claims extends object = Record<string, unknown>
> = Pick<IdentityQuery<Claims>, 'get'> &
    (M extends 'uidBatch' ? Pick<IdentityQuery<Claims>, 'delete'> : {}) &
    (M extends 'base' ? Pick<IdentityQuery<Claims>, 'add' | 'import'> : {}) &
    (M extends 'base' | 'or' ? Pick<IdentityQuery<Claims>, 'or'> : {}) &
    (M extends 'lookup' | 'uidBatch' | 'or'
        ? {}
        : {
              limit(
                  value: number
              ): IdentityQueryBuilder<
                  Modified<M>,
                  Sorted,
                  TokenAllowed,
                  Claims
              >;
          } & (M extends 'token'
              ? {
                    pageToken(
                        token: string
                    ): IdentityQueryBuilder<'token', Sorted, true, Claims>;
                    offset(
                        value: 0
                    ): IdentityQueryBuilder<'token', Sorted, true, Claims>;
                }
              : {
                    count(): IdentityCountQuery;
                    offset<N extends number>(
                        value: N
                    ): IdentityQueryBuilder<
                        Modified<M>,
                        Sorted,
                        N extends 0 ? TokenAllowed : false,
                        Claims
                    >;
                    limitToLast(
                        value: number
                    ): IdentityQueryBuilder<Modified<M>, Sorted, false, Claims>;
                }) &
              (Sorted extends false
                  ? {
                        orderBy<
                            F extends M extends 'token'
                                ? 'uid'
                                : IdentityOrderField,
                            D extends M extends 'token'
                                ? 'asc'
                                : IdentityDirection = 'asc'
                        >(
                            field: F,
                            direction?: D
                        ): IdentityQueryBuilder<
                            Modified<M>,
                            true,
                            TokenAllowed extends true
                                ? IdentityTokenSort<F, D>
                                : false,
                            Claims
                        >;
                    }
                  : {}) &
              (M extends 'base'
                  ? {
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
                    }
                  : {}) &
              (M extends 'base' | 'query'
                  ? {
                        where<
                            F extends M extends 'base'
                                ? IdentityStringFilterField
                                : IdentityNativeFilterField
                        >(
                            field: F,
                            operator: '==',
                            value: string
                        ): IdentityQueryBuilder<
                            F extends 'initialEmail' ? 'lookup' : 'filtered',
                            Sorted,
                            false,
                            Claims
                        >;
                    }
                  : {}) &
              (M extends 'base' | 'query'
                  ? TokenAllowed extends true
                      ? {
                            pageToken(
                                token: string
                            ): IdentityQueryBuilder<
                                'token',
                                Sorted,
                                true,
                                Claims
                            >;
                        }
                      : {}
                  : {}) &
              (M extends 'base'
                  ? {
                        byUid<LookupClaims extends object = Claims>(
                            uid: string
                        ): IdentityReference<false, true, LookupClaims>;
                        byEmail(
                            email: string
                        ): IdentityReference<false, false, Claims>;
                        byPhoneNumber(
                            phoneNumber: string
                        ): IdentityReference<false, false, Claims>;
                        byProvider(
                            providerId: string,
                            providerUid: string
                        ): IdentityReference<false, false, Claims>;
                    }
                  : {}));
