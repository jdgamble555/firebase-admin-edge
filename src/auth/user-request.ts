import { FirebaseAdminAuthErrorInfo, FirebaseEdgeError } from './errors.js';
import type { UpdateAccountRequest } from './firebase-types.js';

/** Serialize stored claims; null clears them. Shared by updates and imports. */
export function buildCustomClaimsRequest(
    claims: object | null
):
    | { data: { customAttributes: string }; error: null }
    | { data: null; error: FirebaseEdgeError } {
    if (claims === null)
        return { data: { customAttributes: '{}' }, error: null };
    if (typeof claims !== 'object' || Array.isArray(claims)) {
        return {
            data: null,
            error: new FirebaseEdgeError({
                ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                message: 'Claims must be an object or null.'
            })
        };
    }
    try {
        const customAttributes = JSON.stringify(claims);
        const serialized = JSON.parse(customAttributes);
        if (
            !serialized ||
            typeof serialized !== 'object' ||
            Array.isArray(serialized)
        )
            throw new Error('Claims must serialize to a JSON object.');
        const reserved = [
            'acr',
            'amr',
            'at_hash',
            'aud',
            'auth_time',
            'azp',
            'cnf',
            'c_hash',
            'exp',
            'iat',
            'iss',
            'jti',
            'nbf',
            'nonce',
            'sub',
            'firebase'
        ];
        if (Object.keys(serialized).some((key) => reserved.includes(key)))
            throw new Error('Claims contain a reserved claim.');
        if (customAttributes.length > 1000)
            throw new Error(
                'Claims must not exceed 1000 characters when JSON-encoded.'
            );
        return { data: { customAttributes }, error: null };
    } catch (cause) {
        return {
            data: null,
            error: new FirebaseEdgeError({
                ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                message:
                    cause instanceof Error
                        ? cause.message
                        : 'Invalid custom claims.'
            })
        };
    }
}

export interface UidIdentifier {
    uid: string;
}
export interface EmailIdentifier {
    email: string;
}
export interface PhoneIdentifier {
    phoneNumber: string;
}
export interface ProviderIdentifier {
    providerId: string;
    providerUid: string;
}
export type UserIdentifier =
    | { initialEmail: string }
    | UidIdentifier
    | EmailIdentifier
    | PhoneIdentifier
    | ProviderIdentifier;

export interface UsersLookupRequest {
    initialEmail?: string[];
    localId?: string[];
    email?: string[];
    phoneNumber?: string[];
    federatedUserId?: { providerId: string; rawId: string }[];
}

/** Validate a batch and group its identifiers for the accounts lookup endpoint. */
export function buildUsersLookupRequest(
    identifiers: UserIdentifier[]
):
    | { data: UsersLookupRequest; error: null }
    | { data: null; error: FirebaseEdgeError } {
    if (!Array.isArray(identifiers) || identifiers.length > 100) {
        return {
            data: null,
            error: new FirebaseEdgeError({
                ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                message:
                    'identifiers must be an array of at most 100 user identifiers.'
            })
        };
    }
    const data: UsersLookupRequest = {};
    for (const id of identifiers) {
        if (!id || typeof id !== 'object' || Array.isArray(id)) {
            return {
                data: null,
                error: new FirebaseEdgeError(
                    FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT
                )
            };
        }
        if ('uid' in id) {
            const error = validateUserUid(id.uid);
            if (error) return { data: null, error };
            (data.localId ??= []).push(id.uid);
            continue;
        }
        if ('email' in id || 'initialEmail' in id) {
            const field = 'email' in id ? 'email' : 'initialEmail';
            const email = 'email' in id ? id.email : id.initialEmail;
            if (
                typeof email !== 'string' ||
                email.length >= 256 ||
                !/^[^\s@]+@[^\s@]+$/.test(email)
            ) {
                return {
                    data: null,
                    error: new FirebaseEdgeError({
                        ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                        message: 'Invalid email identifier.'
                    })
                };
            }
            (data[field] ??= []).push(email);
            continue;
        }
        if ('phoneNumber' in id) {
            if (
                typeof id.phoneNumber !== 'string' ||
                !/^\+[0-9][0-9 .()\-]*$/.test(id.phoneNumber)
            ) {
                return {
                    data: null,
                    error: new FirebaseEdgeError({
                        ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                        message: 'Invalid phone number identifier.'
                    })
                };
            }
            (data.phoneNumber ??= []).push(id.phoneNumber);
            continue;
        }
        if (
            'providerId' in id &&
            'providerUid' in id &&
            typeof id.providerId === 'string' &&
            id.providerId &&
            typeof id.providerUid === 'string' &&
            id.providerUid
        ) {
            (data.federatedUserId ??= []).push({
                providerId: id.providerId,
                rawId: id.providerUid
            });
            continue;
        }
        return {
            data: null,
            error: new FirebaseEdgeError(
                FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT
            )
        };
    }
    return { data, error: null };
}

export interface CreatePhoneMultiFactorInfoRequest {
    factorId: string;
    phoneNumber: string;
    displayName?: string;
}
export interface UpdatePhoneMultiFactorInfoRequest
    extends CreatePhoneMultiFactorInfoRequest {
    uid?: string;
    enrollmentTime?: string;
}
export interface UserProvider {
    uid?: string;
    providerId?: string;
    displayName?: string;
    email?: string;
    phoneNumber?: string;
    photoURL?: string;
}
export interface CreateRequest {
    uid?: string;
    email?: string;
    emailVerified?: boolean;
    password?: string;
    displayName?: string;
    photoURL?: string;
    phoneNumber?: string;
    disabled?: boolean;
    multiFactor?: { enrolledFactors: CreatePhoneMultiFactorInfoRequest[] };
}
export interface UpdateRequest {
    email?: string;
    emailVerified?: boolean;
    password?: string;
    displayName?: string | null;
    photoURL?: string | null;
    phoneNumber?: string | null;
    disabled?: boolean;
    multiFactor?: {
        enrolledFactors: UpdatePhoneMultiFactorInfoRequest[] | null;
    };
    providerToLink?: UserProvider;
    providersToUnlink?: string[];
}

/** Validate a UID before any credential or API requests. */
export function validateUserUid(uid: string): FirebaseEdgeError | null {
    if (typeof uid !== 'string' || uid.length === 0) {
        return new FirebaseEdgeError(
            FirebaseAdminAuthErrorInfo.ADMIN_INVALID_UID
        );
    }
    if (uid.length > 128) {
        return new FirebaseEdgeError(
            FirebaseAdminAuthErrorInfo.ADMIN_UID_TOO_LONG
        );
    }
    return null;
}

/** Validate SDK properties and translate them into the admin API wire format. */
export function buildUserRequest(
    properties: CreateRequest | UpdateRequest,
    operation: 'create' | 'update'
):
    | { data: UpdateAccountRequest; error: null }
    | { data: null; error: FirebaseEdgeError } {
    try {
        if (
            !properties ||
            typeof properties !== 'object' ||
            Array.isArray(properties)
        ) {
            throw new Error('User properties must be a non-null object.');
        }
        const input = properties as CreateRequest & UpdateRequest;
        for (const forbidden of [
            'tenantId',
            'customAttributes',
            'validSince'
        ]) {
            if (forbidden in input)
                throw new Error(
                    `${forbidden} is not a user management property.`
                );
        }
        if (operation === 'create' && input.uid !== undefined) {
            const error = validateUserUid(input.uid);
            if (error) return { data: null, error };
        }
        const body: UpdateAccountRequest = {};
        for (const field of ['emailVerified', 'disabled'] as const) {
            if (input[field] === undefined) continue;
            if (typeof input[field] !== 'boolean')
                throw new Error(`${field} must be a boolean.`);
            body[
                field === 'disabled' && operation === 'update'
                    ? 'disableUser'
                    : field
            ] = input[field];
        }
        if (input.email !== undefined) {
            if (
                typeof input.email !== 'string' ||
                !/^[^\s@]+@[^\s@]+$/.test(input.email)
            )
                throw new Error('email must be a valid email address.');
            body.email = input.email;
        }
        if (input.password !== undefined) {
            if (typeof input.password !== 'string' || input.password.length < 6)
                throw new Error(
                    'password must contain at least six characters.'
                );
            body.password = input.password;
        }
        for (const field of [
            'displayName',
            'photoURL',
            'phoneNumber'
        ] as const) {
            const value = input[field];
            if (value === undefined) continue;
            if (value === null && operation === 'update') {
                if (field === 'phoneNumber') {
                    body.deleteProvider = ['phone'];
                    continue;
                }
                body.deleteAttribute ??= [];
                body.deleteAttribute.push(
                    field === 'photoURL' ? 'PHOTO_URL' : 'DISPLAY_NAME'
                );
                continue;
            }
            if (typeof value !== 'string')
                throw new Error(`${field} must be a string.`);
            if (field === 'phoneNumber' && !/^\+[0-9][0-9 .()\-]*$/.test(value))
                throw new Error(
                    'phoneNumber must be a valid international phone number.'
                );
            if (field === 'photoURL' && value !== '') {
                const url = new URL(value);
                if (!url.hostname)
                    throw new Error('photoURL must be a valid URL.');
            }
            body[field === 'photoURL' ? 'photoUrl' : field] = value;
        }
        if (operation === 'create' && input.uid !== undefined)
            body.localId = input.uid;
        if (operation === 'update' && input.providersToUnlink !== undefined) {
            if (
                !Array.isArray(input.providersToUnlink) ||
                input.providersToUnlink.some(
                    (id) => typeof id !== 'string' || !id
                )
            )
                throw new Error(
                    'providersToUnlink must be an array of non-empty strings.'
                );
            body.deleteProvider = [
                ...(body.deleteProvider ?? []),
                ...input.providersToUnlink
            ];
        }
        if (operation === 'update' && input.providerToLink !== undefined) {
            const provider = input.providerToLink;
            if (
                !provider ||
                typeof provider.uid !== 'string' ||
                !provider.uid ||
                typeof provider.providerId !== 'string' ||
                !provider.providerId
            )
                throw new Error('providerToLink requires uid and providerId.');
            body.linkProviderUserInfo = {
                rawId: provider.uid,
                providerId: provider.providerId,
                displayName: provider.displayName,
                email: provider.email,
                phoneNumber: provider.phoneNumber,
                photoUrl: provider.photoURL
            };
        }
        if (input.multiFactor !== undefined) {
            if (!input.multiFactor || typeof input.multiFactor !== 'object')
                throw new Error('multiFactor must be an object.');
            const factors = input.multiFactor.enrolledFactors;
            if (factors === null && operation === 'update')
                return { data: { ...body, mfa: {} }, error: null };
            if (!Array.isArray(factors))
                throw new Error('enrolledFactors must be an array.');
            const enrollments = factors.map(
                (factor: UpdatePhoneMultiFactorInfoRequest) => {
                    if (!factor || factor.factorId !== 'phone')
                        throw new Error(
                            'Only phone second factors are supported.'
                        );
                    if (
                        typeof factor.phoneNumber !== 'string' ||
                        !/^\+[0-9][0-9 .()\-]*$/.test(factor.phoneNumber)
                    )
                        throw new Error(
                            'A second factor requires an international phoneNumber.'
                        );
                    if (
                        operation === 'create' &&
                        ('uid' in factor || 'enrollmentTime' in factor)
                    )
                        throw new Error(
                            'New second factors cannot specify uid or enrollmentTime.'
                        );
                    if (factor.uid !== undefined && validateUserUid(factor.uid))
                        throw new Error('Invalid second factor uid.');
                    if (
                        factor.displayName !== undefined &&
                        typeof factor.displayName !== 'string'
                    )
                        throw new Error(
                            'Second factor displayName must be a string.'
                        );
                    if (
                        factor.enrollmentTime !== undefined &&
                        (typeof factor.enrollmentTime !== 'string' ||
                            Number.isNaN(Date.parse(factor.enrollmentTime)))
                    )
                        throw new Error(
                            'Invalid second factor enrollmentTime.'
                        );
                    return {
                        phoneInfo: factor.phoneNumber,
                        ...(factor.uid !== undefined && {
                            mfaEnrollmentId: factor.uid
                        }),
                        ...(factor.displayName !== undefined && {
                            displayName: factor.displayName
                        }),
                        ...(factor.enrollmentTime !== undefined && {
                            enrolledAt: new Date(
                                factor.enrollmentTime
                            ).toISOString()
                        })
                    };
                }
            );
            if (operation === 'update')
                body.mfa = enrollments.length ? { enrollments } : {};
            if (operation === 'create' && enrollments.length)
                body.mfaInfo = enrollments;
        }
        return { data: body, error: null };
    } catch (cause) {
        return {
            data: null,
            error: new FirebaseEdgeError({
                ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                message:
                    cause instanceof Error
                        ? cause.message
                        : 'Invalid user properties.'
            })
        };
    }
}
