import type { UserInfo, UserMetadata } from './firebase-types.js';
import type { UserIdentifier } from './user-request.js';

export interface GetUsersResult {
    users: UserRecord[];
    notFound: UserIdentifier[];
}

/** Convert a batch lookup response and retain identifiers with no matching user. */
export function createGetUsersResult(
    identifiers: UserIdentifier[],
    response: ListUsersResponse
): GetUsersResult {
    const users = (response.users ?? []).map(createUserRecord);
    const notFound = identifiers.filter(
        (id) =>
            !users.some((user) => {
                if ('uid' in id) return id.uid === user.uid;
                if ('email' in id) return id.email === user.email;
                if ('initialEmail' in id)
                    return id.initialEmail === user.initialEmail;
                if ('phoneNumber' in id)
                    return id.phoneNumber === user.phoneNumber;
                return (
                    user.providerData.find(
                        (provider) => provider.providerId === id.providerId
                    )?.uid === id.providerUid
                );
            })
    );
    return { users, notFound };
}

type Serializable<T> = T & { toJSON(): object };

export interface ListUsersResult {
    users: UserRecord[];
    pageToken?: string;
}

export interface UserRecord {
    readonly initialEmail?: string;
    readonly uid: string;
    readonly email?: string;
    readonly emailVerified: boolean;
    readonly displayName?: string;
    readonly photoURL?: string;
    readonly phoneNumber?: string;
    readonly disabled: boolean;
    readonly metadata: Serializable<UserMetadata>;
    readonly providerData: Serializable<{
        uid: string;
        providerId: string;
        email?: string;
        displayName?: string;
        photoURL?: string;
        phoneNumber?: string;
    }>[];
    readonly passwordHash?: string;
    readonly passwordSalt?: string;
    readonly customClaims?: Record<string, any>;
    readonly tokensValidAfterTime?: string;
    readonly tenantId?: string;
    readonly multiFactor?: Serializable<{
        enrolledFactors: Serializable<{
            uid: string;
            displayName?: string;
            factorId: string;
            enrollmentTime?: string | null;
            phoneNumber?: string;
            totpInfo?: Record<string, unknown>;
        }>[];
    }>;
    toJSON(): object;
}

export interface ListUsersResponse {
    users?: (UserInfo & {
        phoneNumber?: string;
        passwordHash?: string;
        salt?: string;
        tenantId?: string;
        mfaInfo?: {
            mfaEnrollmentId: string;
            displayName?: string;
            enrolledAt?: string;
            phoneInfo?: string;
            totpInfo?: Record<string, unknown>;
        }[];
    })[];
    nextPageToken?: string;
}

/** Add SDK-style JSON snapshots without introducing Node.js dependencies. */
function withJSON<T extends object>(value: T): Serializable<T> {
    return Object.defineProperty(value, 'toJSON', {
        value() {
            // Non-enumerable methods are omitted, including on nested records.
            return structuredClone(this);
        }
    }) as Serializable<T>;
}

function timestampToUTC(value: string | number | undefined): string | null {
    if (value === undefined) return null;
    const date = new Date(Number.parseInt(String(value), 10));
    if (Number.isNaN(date.getTime())) return null;
    return date.toUTCString();
}

/** Convert the batchGet wire format to the Firebase Admin user record shape. */
export function createUserRecord(
    user: NonNullable<ListUsersResponse['users']>[number]
): UserRecord {
    if (!user.localId)
        throw new Error('Invalid user response: missing localId.');

    const providerData = (user.providerUserInfo ?? []).map((provider) => {
        if (!provider.rawId || !provider.providerId) {
            throw new Error(
                'Invalid provider response: missing user or provider ID.'
            );
        }
        return withJSON({
            uid: provider.rawId,
            providerId: provider.providerId,
            email: provider.email,
            displayName: provider.displayName,
            photoURL: provider.photoUrl,
            phoneNumber: provider.phoneNumber
        });
    });
    const enrolledFactors: NonNullable<
        UserRecord['multiFactor']
    >['enrolledFactors'] = [];
    for (const factor of user.mfaInfo ?? []) {
        if (!factor?.mfaEnrollmentId) continue;
        const isPhone = factor.phoneInfo !== undefined;
        if (isPhone && !factor.phoneInfo) continue;
        if (!isPhone && !factor.totpInfo) continue;
        enrolledFactors.push(
            withJSON({
                uid: factor.mfaEnrollmentId,
                displayName: factor.displayName,
                factorId: isPhone ? 'phone' : 'totp',
                enrollmentTime: factor.enrolledAt
                    ? new Date(factor.enrolledAt).toUTCString()
                    : null,
                ...(isPhone
                    ? { phoneNumber: factor.phoneInfo }
                    : { totpInfo: factor.totpInfo })
            })
        );
    }

    return withJSON({
        uid: user.localId,
        ...(user.initialEmail !== undefined && {
            initialEmail: user.initialEmail
        }),
        email: user.email,
        emailVerified: !!user.emailVerified,
        displayName: user.displayName,
        photoURL: user.photoUrl,
        phoneNumber: user.phoneNumber,
        disabled: user.disabled || false,
        metadata: withJSON({
            creationTime: timestampToUTC(user.createdAt),
            lastSignInTime: timestampToUTC(user.lastLoginAt),
            lastRefreshTime: user.lastRefreshAt
                ? new Date(user.lastRefreshAt).toUTCString()
                : null
        }),
        providerData,
        passwordHash:
            user.passwordHash === 'UkVEQUNURUQ='
                ? undefined
                : user.passwordHash,
        passwordSalt: user.salt,
        ...(user.customAttributes && {
            customClaims: JSON.parse(user.customAttributes)
        }),
        tokensValidAfterTime:
            user.validSince === undefined
                ? undefined
                : (timestampToUTC(
                      Number.parseInt(user.validSince, 10) * 1000
                  ) ?? undefined),
        tenantId: user.tenantId,
        ...(enrolledFactors.length > 0 && {
            multiFactor: withJSON({
                enrolledFactors: Object.freeze(
                    enrolledFactors
                ) as typeof enrolledFactors
            })
        })
    });
}
