import { FirebaseEdgeError } from './auth/errors.js';
import type { FirebaseAdminAuth } from './auth/firebase-admin-auth.js';
import { createUserRecord } from './auth/user-record.js';
import { buildUserRequest, validateUserUid } from './auth/user-request.js';
import type { Firestore } from './db/firestore.js';
import { validatePath } from './db/firestore-path.js';
import { firestoreData, firestoreResult } from './db/firestore-results.js';
import type { Storage } from './storage/storage.js';
import {
    profilePhotoPath,
    PROFILE_PHOTO_CONTENT_TYPES,
    hasPhotoSignature,
    isProfilePhotoPath
} from './profiles-photo.js';

export interface ProfilePhotoUpdateOptions {
    /** Preserve the old stored image. Defaults to false. */
    keepOldPhoto?: boolean;
}

export interface PhotoUploadOptions {
    /** Defaults to image/jpeg. */
    contentType?:
        | 'image/jpeg'
        | 'image/png'
        | 'image/webp'
        | 'image/gif'
        | 'image/avif';
    /** Signed URL lifetime in seconds; defaults to 900. */
    expiresInSeconds?: number;
}

export interface ProfileUpdate {
    displayName?: string | null;
    photoURL?: string | null;
}

export interface GetProfileOptions {
    /** Include selected Auth fields, requiring an additional Auth lookup. Defaults to false. */
    includeAuth?: boolean;
}

export interface ResumablePhotoUploadOptions
    extends Pick<PhotoUploadOptions, 'contentType'> {
    /** Total file size in bytes, declared when creating the session. */
    size: number;
    /** Browser origin to forward when initiating the upload session. */
    origin?: string;
}

/** Server-side profiles and unique username reservations. */
export class Profiles {
    constructor(
        readonly firestore: Firestore,
        readonly adminAuth: FirebaseAdminAuth,
        readonly usernamesCollection = 'usernames',
        readonly usersCollection = 'users',
        readonly storage?: Storage,
        readonly profilePhotosPath = 'profile-photos',
        readonly profilePhotoMaxBytes: number | null = 8 * 1024 * 1024
    ) {
        validatePath(usernamesCollection, false);
        validatePath(usersCollection, false);
        if (
            profilePhotoMaxBytes !== null &&
            (!Number.isSafeInteger(profilePhotoMaxBytes) ||
                profilePhotoMaxBytes < 1)
        ) {
            throw new FirebaseEdgeError({
                code: 'profiles/invalid-photo-size',
                message:
                    'Profile photo maximum must be a positive safe integer or null.'
            });
        }
        if (
            typeof profilePhotosPath !== 'string' ||
            /[\\\u0000-\u001f\u007f]/.test(profilePhotosPath) ||
            profilePhotosPath
                .split('/')
                .some(
                    (segment) =>
                        !segment.trim() || segment === '.' || segment === '..'
                )
        ) {
            throw new FirebaseEdgeError({
                code: 'profiles/invalid-photo-path',
                message:
                    'Profile photos path must contain non-empty segments without dot segments or control characters.'
            });
        }
        if (usersCollection === usernamesCollection) {
            throw new FirebaseEdgeError({
                code: 'profiles/invalid-collection',
                message:
                    'Users and username reservations must use different collections.'
            });
        }
    }

    /** Return the canonical username or reject invalid names. */
    private normalizeUsername(username: string): string {
        if (
            typeof username !== 'string' ||
            !/^[a-zA-Z0-9_]{3,30}$/.test(username)
        ) {
            throw new FirebaseEdgeError({
                code: 'profiles/invalid-username',
                message:
                    'Usernames must contain 3–30 letters, numbers, or underscores.'
            });
        }
        return username.toLowerCase();
    }

    /** Check availability; only updateUsername reserves a name. */
    async checkUsername(username: string) {
        return firestoreResult(async () => {
            const normalized = this.normalizeUsername(username);
            const ref = this.firestore.doc(
                `${this.usernamesCollection}/${normalized}`
            );
            const result = await ref.get();
            const snapshot = firestoreData(result);
            return !snapshot.exists;
        });
    }

    /** Read the Firestore profile, optionally merging authoritative Auth fields. */
    async getProfile(uid: string, options: GetProfileOptions = {}) {
        return firestoreResult(async () => {
            const error = validateUserUid(uid);
            if (error) {
                throw error;
            }
            if (
                !options ||
                typeof options !== 'object' ||
                Array.isArray(options) ||
                (options.includeAuth !== undefined &&
                    typeof options.includeAuth !== 'boolean')
            ) {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-profile-options',
                    message: 'includeAuth must be a boolean.'
                });
            }
            const ref = this.firestore.doc(
                `${this.usersCollection}/${encodeURIComponent(uid)}`
            );
            const result = await ref.get();
            const snapshot = firestoreData(result);
            const profile = snapshot.data() ?? null;
            if (!options.includeAuth) {
                return profile;
            }

            const { error: authError, data: user } =
                await this.adminAuth.getUser(uid);
            if (authError) {
                throw authError;
            }
            if (!user) {
                throw new FirebaseEdgeError({
                    code: 'profiles/user-not-found',
                    message: 'The user does not exist.'
                });
            }
            return {
                ...profile,
                uid: user.localId,
                displayName: user.displayName ?? null,
                photoURL: user.photoUrl ?? null
            };
        });
    }

    private preparePhotoUpload(
        uid: string,
        options: Pick<PhotoUploadOptions, 'contentType'>
    ) {
        const uidError = validateUserUid(uid);
        if (uidError) {
            throw uidError;
        }
        if (!options || typeof options !== 'object' || Array.isArray(options)) {
            throw new FirebaseEdgeError({
                code: 'profiles/invalid-upload-options',
                message: 'Photo upload options must be an object.'
            });
        }
        const { contentType = 'image/jpeg' } = options;
        if (!PROFILE_PHOTO_CONTENT_TYPES.includes(contentType)) {
            throw new FirebaseEdgeError({
                code: 'profiles/invalid-photo-type',
                message:
                    'Photo content type must be JPEG, PNG, WebP, GIF, or AVIF.'
            });
        }
        if (!this.storage) {
            throw new FirebaseEdgeError({
                code: 'profiles/storage-required',
                message: 'Storage is required to create photo upload URLs.'
            });
        }

        const path = `${this.profilePhotosPath}/${encodeURIComponent(uid)}/${crypto.randomUUID()}`;
        return { path, contentType, storage: this.storage };
    }

    /** Create a resumable session without changing the user's current profile. */
    async createResumablePhotoUploadUrl(
        uid: string,
        options: ResumablePhotoUploadOptions
    ) {
        return firestoreResult(async () => {
            const { path, contentType, storage } = this.preparePhotoUpload(
                uid,
                options
            );
            const { size, origin } = options;
            if (!Number.isSafeInteger(size) || size < 1) {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-photo-size',
                    message: 'Photo size must be a positive safe integer.'
                });
            }
            if (
                this.profilePhotoMaxBytes !== null &&
                size > this.profilePhotoMaxBytes
            ) {
                throw new FirebaseEdgeError({
                    code: 'profiles/photo-too-large',
                    message: 'Photo exceeds the configured maximum size.'
                });
            }

            const { error, data: uploadUrl } =
                await storage.createResumableUpload(path, {
                    contentType,
                    size,
                    origin
                });
            if (error) {
                throw error;
            }
            return {
                uploadUrl,
                path,
                contentType,
                size,
                maxBytes: this.profilePhotoMaxBytes
            };
        });
    }

    /** Create a signed PUT URL for a new profile photo in the configured bucket. */
    async createPhotoUploadUrl(uid: string, options: PhotoUploadOptions = {}) {
        return firestoreResult(async () => {
            const { path, contentType, storage } = this.preparePhotoUpload(
                uid,
                options
            );
            const { expiresInSeconds = 900 } = options;
            const { error, data: uploadUrl } = await storage.getSignedUrl(
                path,
                {
                    action: 'write',
                    contentType,
                    expiresInSeconds,
                    maxBytes: this.profilePhotoMaxBytes ?? undefined
                }
            );
            if (error) {
                throw error;
            }
            const headers: Record<string, string> = {
                'Content-Type': contentType
            };
            if (this.profilePhotoMaxBytes !== null) {
                headers['x-goog-content-length-range'] =
                    `0,${this.profilePhotoMaxBytes}`;
            }
            return {
                uploadUrl,
                path,
                contentType,
                headers,
                maxBytes: this.profilePhotoMaxBytes
            };
        });
    }

    /** Verify an uploaded object and publish its Firebase download URL. */
    async completePhotoUpload(uid: string, path: string) {
        return firestoreResult(async () => {
            const uidError = validateUserUid(uid);
            if (uidError) {
                throw uidError;
            }
            if (!isProfilePhotoPath(path, this.profilePhotosPath, uid)) {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-photo-path',
                    message:
                        'Upload path must belong to this user’s configured photo directory.'
                });
            }
            if (!this.storage) {
                throw new FirebaseEdgeError({
                    code: 'profiles/storage-required',
                    message: 'Storage is required to complete a photo upload.'
                });
            }

            const { error: metadataError, data: metadata } =
                await this.storage.getMetadata(path);
            if (metadataError) {
                throw metadataError;
            }
            const size = Number(metadata.size);
            if (!Number.isSafeInteger(size) || size < 1) {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-photo-size',
                    message:
                        'Uploaded photo must have a positive safe integer size.'
                });
            }
            if (
                this.profilePhotoMaxBytes !== null &&
                size > this.profilePhotoMaxBytes
            ) {
                throw new FirebaseEdgeError({
                    code: 'profiles/photo-too-large',
                    message:
                        'Uploaded photo exceeds the configured maximum size.'
                });
            }
            if (
                !metadata.contentType ||
                !PROFILE_PHOTO_CONTENT_TYPES.includes(metadata.contentType)
            ) {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-photo-type',
                    message: 'Uploaded photo has an unsupported content type.'
                });
            }
            const { error: downloadError, data: bytes } =
                await this.storage.download(path, {
                    start: 0,
                    end: 15,
                    generation: metadata.generation
                });
            if (downloadError) {
                throw downloadError;
            }
            if (!hasPhotoSignature(bytes, metadata.contentType)) {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-photo-type',
                    message:
                        'Uploaded photo signature does not match its content type.'
                });
            }

            const token =
                metadata.metadata?.firebaseStorageDownloadTokens?.trim() ||
                crypto.randomUUID();
            const { error: tokenError } = await this.storage.updateMetadata(
                path,
                {
                    metadata: {
                        ...metadata.metadata,
                        firebaseStorageDownloadTokens: token
                    }
                },
                {
                    ifGenerationMatch: metadata.generation,
                    ifMetagenerationMatch: metadata.metageneration
                }
            );
            if (tokenError) {
                throw tokenError;
            }
            const { error: urlError, data: photoURL } =
                await this.storage.downloadURL(path);
            if (urlError) {
                throw urlError;
            }
            const result = await this.updatePhoto(uid, photoURL);
            return firestoreData(result);
        });
    }

    /** Set the photoURL field in Firebase Auth and the Firestore user document. */
    async updatePhoto(
        uid: string,
        photoURL: string,
        options: ProfilePhotoUpdateOptions = {}
    ) {
        return firestoreResult(async () => {
            if (typeof photoURL !== 'string' || !photoURL) {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-photo-url',
                    message: 'A non-empty photo URL is required.'
                });
            }
            const result = await this.updateProfile(uid, { photoURL }, options);
            return firestoreData(result);
        });
    }

    /** Clear the profile references and delete the user's managed stored photo. */
    async removePhoto(uid: string) {
        return this.updateProfile(uid, { photoURL: null });
    }

    /** Update the display name in Auth and the configured Firestore user document. */
    async updateDisplayName(uid: string, displayName: string | null) {
        return this.updateProfile(uid, { displayName });
    }

    /** Merge supplied displayName and photoURL fields into Auth and Firestore. */
    async updateProfile(
        uid: string,
        updates: ProfileUpdate,
        options: ProfilePhotoUpdateOptions = {}
    ) {
        return firestoreResult(async () => {
            const uidError = validateUserUid(uid);
            if (uidError) {
                throw uidError;
            }
            if (
                !options ||
                typeof options !== 'object' ||
                Array.isArray(options) ||
                (options.keepOldPhoto !== undefined &&
                    typeof options.keepOldPhoto !== 'boolean')
            ) {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-photo-options',
                    message: 'keepOldPhoto must be a boolean.'
                });
            }
            if (
                !updates ||
                typeof updates !== 'object' ||
                Array.isArray(updates) ||
                Object.keys(updates).some(
                    (key) => key !== 'displayName' && key !== 'photoURL'
                )
            ) {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-profile',
                    message:
                        'Profile updates may contain only displayName and photoURL.'
                });
            }
            const fields: ProfileUpdate = {};
            if (updates.displayName !== undefined) {
                fields.displayName = updates.displayName;
            }
            if (updates.photoURL !== undefined) {
                fields.photoURL = updates.photoURL;
            }
            if (Object.keys(fields).length === 0) {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-profile',
                    message: 'Supply a displayName or photoURL to update.'
                });
            }
            if (fields.photoURL === '') {
                throw new FirebaseEdgeError({
                    code: 'profiles/invalid-photo-url',
                    message: 'Use null to clear the photo URL.'
                });
            }
            const { error: validationError } = buildUserRequest(
                fields,
                'update'
            );
            if (validationError) {
                throw validationError;
            }
            const userRef = this.firestore.doc(
                `${this.usersCollection}/${encodeURIComponent(uid)}`
            );

            const oldPaths = new Set<string>();
            if (fields.photoURL !== undefined && !options.keepOldPhoto) {
                const result = await userRef.get();
                const snapshot = firestoreData(result);
                const { error: userError, data: user } =
                    await this.adminAuth.getUser(uid);
                if (userError) {
                    throw userError;
                }
                if (!user) {
                    throw new FirebaseEdgeError({
                        code: 'profiles/user-not-found',
                        message: 'The user does not exist.'
                    });
                }
                const newPath = profilePhotoPath(
                    fields.photoURL,
                    this.storage?.bucketName,
                    this.profilePhotosPath,
                    uid
                );
                for (const url of [snapshot.data()?.photoURL, user.photoUrl]) {
                    const path = profilePhotoPath(
                        url,
                        this.storage?.bucketName,
                        this.profilePhotosPath,
                        uid
                    );
                    if (path && path !== newPath) {
                        oldPaths.add(path);
                    }
                }
            }

            const { error: authError } = await this.adminAuth.updateUser(
                uid,
                fields
            );
            if (authError) {
                throw authError;
            }

            const { error: writeError } = await userRef.set(
                { ...fields },
                {
                    merge: true
                }
            );
            if (writeError) {
                throw writeError;
            }
            for (const path of oldPaths) {
                const { error: cleanupError } =
                    await this.deleteStoredPhoto(path);
                if (cleanupError) {
                    throw new FirebaseEdgeError(
                        {
                            code: 'profiles/photo-cleanup-failed',
                            message:
                                'Profile updated, but the old photo could not be deleted.'
                        },
                        { cause: cleanupError, context: { path } }
                    );
                }
            }
            return { uid, ...fields };
        });
    }

    private async deleteStoredPhoto(path: string) {
        return firestoreResult(async () => {
            if (!this.storage) {
                return;
            }
            const { error: metadataError, data: metadata } =
                await this.storage.getMetadata(path);
            if (metadataError?.code === 'storage/object-not-found') {
                return;
            }
            if (metadataError) {
                throw metadataError;
            }
            const { error } = await this.storage.delete(path, {
                ifGenerationMatch: metadata.generation
            });
            if (error?.code === 'storage/object-not-found') {
                return;
            }
            if (error) {
                throw error;
            }
        });
    }

    /** Release username reservations and clear the profile and Auth claim. */
    async removeUsername(uid: string) {
        return firestoreResult(async () => {
            const uidError = validateUserUid(uid);
            if (uidError) {
                throw uidError;
            }
            const { error: userError, data: user } =
                await this.adminAuth.getUser(uid);
            if (userError) {
                throw userError;
            }
            if (!user) {
                throw new FirebaseEdgeError({
                    code: 'profiles/user-not-found',
                    message: 'The user does not exist.'
                });
            }
            const { customClaims } = createUserRecord(user);
            const { username: removedClaim, ...claims } = customClaims ?? {};
            const ownerRef = this.firestore.doc(
                `${this.usernamesCollection}/uid:${encodeURIComponent(uid)}`
            );
            const userRef = this.firestore.doc(
                `${this.usersCollection}/${encodeURIComponent(uid)}`
            );
            const result = await this.firestore.runTransaction(
                async (transaction) => {
                    const ownerResult = await transaction.get(ownerRef);
                    const owner = firestoreData(ownerResult);
                    const profileResult = await transaction.get(userRef);
                    const profile = firestoreData(profileResult);
                    const names = new Set([
                        owner.data()?.username,
                        profile.data()?.username
                    ]);
                    const reservations = [];
                    for (const name of names) {
                        if (typeof name !== 'string') {
                            continue;
                        }
                        const normalized = this.normalizeUsername(name);
                        const ref = this.firestore.doc(
                            `${this.usernamesCollection}/${normalized}`
                        );
                        const nameResult = await transaction.get(ref);
                        const snapshot = firestoreData(nameResult);
                        if (snapshot.data()?.uid === uid) {
                            reservations.push(ref);
                        }
                    }
                    for (const ref of reservations) {
                        transaction.delete(ref);
                    }
                    transaction.delete(ownerRef);
                    transaction.set(
                        userRef,
                        { username: null },
                        { merge: true }
                    );
                    return { uid, username: null };
                }
            );
            const data = firestoreData(result);
            const { error: claimsError } =
                await this.adminAuth.setCustomUserClaims(uid, claims);
            if (claimsError) {
                throw claimsError;
            }
            return data;
        });
    }

    /** Atomically claim a name and release the user's previous reservation. */
    async updateUsername(uid: string, username: string) {
        return firestoreResult(async () => {
            const error = validateUserUid(uid);
            if (error) {
                throw error;
            }
            const normalized = this.normalizeUsername(username);
            const ownerRef = this.firestore.doc(
                `${this.usernamesCollection}/uid:${encodeURIComponent(uid)}`
            );
            const nameRef = this.firestore.doc(
                `${this.usernamesCollection}/${normalized}`
            );
            const userRef = this.firestore.doc(
                `${this.usersCollection}/${encodeURIComponent(uid)}`
            );

            const { error: userError, data: user } =
                await this.adminAuth.getUser(uid);
            if (userError) {
                throw userError;
            }
            if (!user) {
                throw new FirebaseEdgeError({
                    code: 'profiles/user-not-found',
                    message: 'The user does not exist.'
                });
            }
            const { customClaims } = createUserRecord(user);

            const result = await this.firestore.runTransaction(
                async (transaction) => {
                    const ownerResult = await transaction.get(ownerRef);
                    const owner = firestoreData(ownerResult);
                    const nameResult = await transaction.get(nameRef);
                    const name = firestoreData(nameResult);
                    if (name.exists && name.data()?.uid !== uid) {
                        throw new FirebaseEdgeError({
                            code: 'profiles/username-taken',
                            message: 'This username is already taken.'
                        });
                    }

                    const previous = owner.data()?.username;
                    if (
                        typeof previous === 'string' &&
                        previous !== normalized
                    ) {
                        const previousRef = this.firestore.doc(
                            `${this.usernamesCollection}/${this.normalizeUsername(previous)}`
                        );
                        const previousResult =
                            await transaction.get(previousRef);
                        const previousName = firestoreData(previousResult);
                        if (previousName.data()?.uid === uid) {
                            transaction.delete(previousRef);
                        }
                    }

                    transaction.set(nameRef, { uid });
                    transaction.set(ownerRef, { username: normalized });
                    transaction.set(
                        userRef,
                        { username: normalized },
                        { merge: true }
                    );
                    return { uid, username: normalized };
                }
            );
            const data = firestoreData(result);
            const { error: claimsError } =
                await this.adminAuth.setCustomUserClaims(uid, {
                    ...customClaims,
                    username: normalized
                });
            if (claimsError) {
                throw claimsError;
            }
            return data;
        });
    }
}
