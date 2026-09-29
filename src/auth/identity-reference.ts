import type {
    IdentityUpdateData,
    IdentitySetData,
    IdentityWriteResult
} from './identity-write.js';
import type { UserMetadataRequest } from './user-import.js';
import type {
    ActionCodeSettings,
    FirebaseAdminAuth
} from './firebase-admin-auth.js';
import {
    buildUsersLookupRequest,
    buildCustomClaimsRequest,
    type UserIdentifier
} from './user-request.js';
import type { UserRecord } from './user-record.js';
import { ensureError, FirebaseEdgeError } from './errors.js';

export type IdentityUserRecord<
    Claims extends object = Record<string, unknown>
> = Omit<UserRecord, 'customClaims'> & {
    readonly customClaims?: Partial<Claims>;
};

type IdentityWriteResponse =
    | { error: null; data: IdentityWriteResult }
    | { error: Error; data: null };

export interface IdentityReferenceOptions<
    Multiple extends boolean = false,
    Uid extends boolean = false
> {
    /** Return an array of matches instead of one user or null. Defaults to false. */
    multiple?: Multiple;
    /** Enable mutations for a single UID identifier. Defaults to false. */
    uidReference?: Uid;
}

/** Exact lookup with no query modifiers or count operation. */
export class IdentityReference<
    Multiple extends boolean = false,
    Uid extends boolean = false,
    Claims extends object = Record<string, unknown>
> {
    private readonly identifier: UserIdentifier;
    private readonly multiple: Multiple;
    private readonly uidReference: Uid;
    private claimsResource?: IdentityClaims<Claims>;
    private metadataResource?: IdentityMetadata;

    constructor(
        private readonly auth: FirebaseAdminAuth,
        identifier: UserIdentifier,
        options: IdentityReferenceOptions<Multiple, Uid> = {}
    ) {
        if (
            !options ||
            typeof options !== 'object' ||
            Array.isArray(options) ||
            (options.multiple !== undefined &&
                typeof options.multiple !== 'boolean') ||
            (options.uidReference !== undefined &&
                typeof options.uidReference !== 'boolean')
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message:
                    'IdentityReference options must be an object with boolean multiple and uidReference settings.'
            });
        }
        const { error } = buildUsersLookupRequest([identifier]);
        if (error) {
            throw error;
        }
        this.identifier = { ...identifier };
        this.multiple = options.multiple ?? (false as Multiple);
        this.uidReference = options.uidReference ?? (false as Uid);
    }

    update(
        this: IdentityReference<false, true, Claims>,
        data: IdentityUpdateData<Claims>
    ) {
        const uid = this.requireUid();
        return this.auth._writeIdentityUser(uid, data);
    }

    set(
        this: IdentityReference<false, true, Claims>,
        data: IdentitySetData<Claims>
    ) {
        const uid = this.requireUid();
        return this.auth._writeIdentityUser(uid, data, 'set');
    }

    /** Disable sign-in for this user. */
    disable(this: IdentityReference<false, true, Claims>) {
        return this.update({ disabled: true });
    }

    /** Enable sign-in for this user. */
    enable(this: IdentityReference<false, true, Claims>) {
        return this.update({ disabled: false });
    }

    /** Ask Firebase to send a password-reset email to this user. */
    resetPassword(
        this: IdentityReference<false, true, Claims>,
        settings?: ActionCodeSettings
    ) {
        const uid = this.requireUid();
        return this.sendPasswordResetEmail(uid, settings);
    }

    private async sendPasswordResetEmail(
        uid: string,
        settings?: ActionCodeSettings
    ) {
        const { error, data } = await readIdentityUser(this.auth, uid);
        if (error) {
            return { error, data: null };
        }
        if (!data.email) {
            return {
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-email',
                    message:
                        'Password reset requires a user with an email address.'
                }),
                data: null
            };
        }

        return identityWriteResult(
            uid,
            this.auth._sendPasswordResetEmail(data.email, settings)
        );
    }

    /** Custom-claims operations for a UID reference; accessing this performs no I/O. */
    get claims(): Uid extends true
        ? Multiple extends false
            ? IdentityClaims<Claims>
            : never
        : never {
        const uid = this.requireUid();
        this.claimsResource ??= new IdentityClaims<Claims>(this.auth, uid);
        return this.claimsResource as Uid extends true
            ? Multiple extends false
                ? IdentityClaims<Claims>
                : never
            : never;
    }

    /** Writable timestamps for a UID reference; accessing this performs no I/O. */
    get metadata(): Uid extends true
        ? Multiple extends false
            ? IdentityMetadata
            : never
        : never {
        const uid = this.requireUid();
        this.metadataResource ??= new IdentityMetadata(this.auth, uid);
        return this.metadataResource as Uid extends true
            ? Multiple extends false
                ? IdentityMetadata
                : never
            : never;
    }

    delete(this: IdentityReference<false, true, Claims>) {
        const uid = this.requireUid();
        return identityWriteResult(uid, this.auth.deleteUser(uid));
    }

    private requireUid(): string {
        if (
            this.multiple ||
            !this.uidReference ||
            !('uid' in this.identifier)
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'This mutation requires a UID reference.'
            });
        }
        return this.identifier.uid;
    }

    /** Check whether an exact single-user lookup matches an account. */
    async exists(
        this: IdentityReference<false, Uid, Claims>
    ): Promise<{ error: null; data: boolean } | { error: Error; data: null }> {
        if (this.multiple) {
            return {
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-argument',
                    message: 'exists requires a single-user lookup.'
                }),
                data: null
            };
        }
        const { error, data } = await this.get();
        if (error) {
            return { error, data: null };
        }
        return { error: null, data: data !== null };
    }

    async get(): Promise<
        | {
              error: null;
              data: Multiple extends true
                  ? IdentityUserRecord<Claims>[]
                  : IdentityUserRecord<Claims> | null;
          }
        | { error: Error; data: null }
    > {
        try {
            const { error, data } = await this.auth.getUsers([this.identifier]);
            if (error) {
                return { error, data: null };
            }
            return {
                error: null,
                data: (this.multiple
                    ? data.users
                    : (data.users[0] ?? null)) as Multiple extends true
                    ? IdentityUserRecord<Claims>[]
                    : IdentityUserRecord<Claims> | null
            };
        } catch (cause) {
            return { error: ensureError(cause), data: null };
        }
    }
}

/** Update explicitly supplied account timestamps. Access through user.metadata. */
class IdentityMetadata {
    constructor(
        private readonly auth: FirebaseAdminAuth,
        private readonly uid: string
    ) {}

    update(metadata: UserMetadataRequest) {
        return this.auth._writeIdentityUser(this.uid, metadata, 'metadata');
    }

    async get() {
        const { error, data } = await readIdentityUser(this.auth, this.uid);
        if (error) {
            return { error, data: null };
        }
        return { error: null, data: data.metadata };
    }

    revokeTokens() {
        return identityWriteResult(
            this.uid,
            this.auth.revokeRefreshTokens(this.uid)
        );
    }
}

/** Claims stored on one existing UID. Access through user.claims. */
class IdentityClaims<Claims extends object> {
    constructor(
        private readonly auth: FirebaseAdminAuth,
        private readonly uid: string
    ) {}

    /** Replace all custom claims; null clears them. No read is required. */
    set(claims: Partial<Claims> | null) {
        return identityWriteResult(
            this.uid,
            this.auth.setCustomUserClaims(this.uid, claims)
        );
    }

    async get() {
        const { error, data } = await readIdentityUser(this.auth, this.uid);
        if (error) {
            return { error, data: null };
        }
        return {
            error: null,
            data: (data.customClaims ?? {}) as Partial<Claims>
        };
    }

    /** Select one literal top-level claim key, not a dotted path. */
    byKey<Key extends Extract<keyof Claims, string>>(key: Key) {
        if (typeof key !== 'string' || key.length === 0) {
            throw new FirebaseEdgeError({
                code: 'auth/invalid-argument',
                message: 'A claim key must be a nonempty string.'
            });
        }
        const { error } = buildCustomClaimsRequest({ [key]: null });
        if (error) {
            throw error;
        }
        return new IdentityClaimKey<Claims, Key>(this, key);
    }

    /** Shallow-merge claims using a non-atomic read followed by a write. */
    async update(claims: Partial<Claims>) {
        if (claims === null) {
            return {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-argument',
                    message:
                        'claims.update requires an object; use claims.delete() to clear claims.'
                })
            };
        }
        const { error, data } = buildCustomClaimsRequest(claims);
        if (error) {
            return { data: null, error };
        }
        // Snapshot the patch before the read so caller mutations cannot change it.
        const patch = JSON.parse(data.customAttributes) as Record<
            string,
            unknown
        >;
        try {
            const { error: readError, data: claims } = await this.get();
            if (readError) {
                return { data: null, error: readError };
            }
            return await this.set({ ...claims, ...patch });
        } catch (cause) {
            return { data: null, error: ensureError(cause) };
        }
    }

    /** Clear all custom claims without deleting the user. */
    delete() {
        return this.set(null);
    }
}

/** One claim value. Updates and deletion preserve other top-level claims. */
class IdentityClaimKey<
    Claims extends object,
    Key extends Extract<keyof Claims, string>
> {
    constructor(
        private readonly claims: IdentityClaims<Claims>,
        private readonly key: Key
    ) {}

    /** Set or replace this key's value while preserving the other claims. */
    set(value: Exclude<Claims[Key], undefined>) {
        return this.update(value);
    }

    /** Read one own claim value; an absent key returns undefined. */
    async get(): Promise<
        | { error: null; data: Claims[Key] | undefined }
        | { error: Error; data: null }
    > {
        const { error, data } = await this.claims.get();
        if (error) {
            return { error, data: null };
        }
        return {
            error: null,
            data: Object.hasOwn(data, this.key) ? data[this.key] : undefined
        };
    }

    async update(value: Exclude<Claims[Key], undefined>) {
        if (
            value === undefined ||
            typeof value === 'function' ||
            typeof value === 'symbol'
        ) {
            return {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-argument',
                    message:
                        'A claim value must be JSON-serializable. Use delete() to remove the field.'
                })
            };
        }
        const { error, data } = buildCustomClaimsRequest({
            [this.key]: value
        });
        if (error) {
            return { error, data: null };
        }
        const patch = JSON.parse(data.customAttributes) as Record<
            string,
            unknown
        >;
        if (!Object.hasOwn(patch, this.key)) {
            return {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/invalid-argument',
                    message:
                        'The claim value was omitted during JSON serialization.'
                })
            };
        }
        return this.claims.update(patch as Partial<Claims>);
    }

    async delete() {
        const { error, data } = await this.claims.get();
        if (error) {
            return { error, data: null };
        }
        const remaining = { ...data };
        delete remaining[this.key];
        return this.claims.set(remaining);
    }
}

/** Read one existing account for a UID reference operation. */
async function readIdentityUser(
    auth: FirebaseAdminAuth,
    uid: string
): Promise<{ error: null; data: UserRecord } | { error: Error; data: null }> {
    try {
        const { error, data } = await auth.getUsers([{ uid }]);
        if (error) {
            return { error, data: null };
        }
        const user = data.users[0];
        if (!user) {
            return {
                data: null,
                error: new FirebaseEdgeError({
                    code: 'auth/user-not-found',
                    message: 'The requested user does not exist.'
                })
            };
        }
        return { error: null, data: user };
    } catch (cause) {
        return { data: null, error: ensureError(cause) };
    }
}

/** Normalize successful single-user writes without reading the account back. */
async function identityWriteResult(
    uid: string,
    operation: Promise<{ error: Error | null }>
): Promise<IdentityWriteResponse> {
    try {
        const { error } = await operation;
        if (error) {
            return { error, data: null };
        }
        return { error: null, data: { uid } };
    } catch (cause) {
        return { error: ensureError(cause), data: null };
    }
}
