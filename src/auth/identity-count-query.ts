import type { FirebaseAdminAuth } from './firebase-admin-auth.js';
import { FirebaseEdgeError, ensureError } from './errors.js';
import { validateIdentityQueryOptions } from './identity-filter.js';
import type {
    IdentityCountResult,
    IdentityQueryOptions
} from './identity-types.js';

/** Count-only query. Uses the same server filter as IdentityQuery. */
export class IdentityCountQuery {
    constructor(
        private readonly auth: FirebaseAdminAuth,
        private readonly options: IdentityQueryOptions = {},
        private readonly pageToken?: string
    ) {}

    async get(): Promise<
        | { data: IdentityCountResult; error: null }
        | { data: null; error: Error }
    > {
        try {
            validateIdentityQueryOptions(this.options);
            if (
                this.options.identifiers !== undefined ||
                this.options.filter?.field === 'initialEmail' ||
                this.options.filter?.operator === 'in'
            ) {
                return {
                    data: null,
                    error: new FirebaseEdgeError({
                        code: 'auth/invalid-argument',
                        message:
                            'Lookup filters do not support count-only requests.'
                    })
                };
            }
            if (this.pageToken !== undefined) {
                return {
                    data: null,
                    error: new FirebaseEdgeError({
                        code: 'auth/invalid-argument',
                        message:
                            'Cannot count from an opaque page token. Use a filter and an optional offset and limit.'
                    })
                };
            }
            const { error, data } = await this.auth._countUsers(
                this.options.filter
            );
            if (error) {
                return { data: null, error };
            }
            const remaining = Math.max(0, data - (this.options.offset ?? 0));
            const count =
                this.options.limit === undefined
                    ? remaining
                    : Math.min(remaining, this.options.limit);
            return { data: { count }, error: null };
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }
}
