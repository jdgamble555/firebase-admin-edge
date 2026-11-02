import { describe, expect, it, vi } from 'vitest';
import { Profiles } from './profiles.js';
import type { Firestore } from './db/firestore.js';
import type { FirebaseAdminAuth } from './auth/firebase-admin-auth.js';
import type { Storage } from './storage/storage.js';

function setup(
    path = 'usernames',
    usersCollection = 'users',
    profilePhotosPath?: string,
    profilePhotoMaxBytes?: number | null
) {
    const documents = new Map<string, Record<string, string | null>>();
    const snapshot = (ref: { path: string }) => ({
        exists: documents.has(ref.path),
        data: () => documents.get(ref.path)
    });
    const transaction = {
        get: vi.fn(async (ref) => ({ error: null, data: snapshot(ref) })),
        set: vi.fn((ref, value, options?: { merge?: boolean }) =>
            documents.set(
                ref.path,
                options?.merge
                    ? { ...documents.get(ref.path), ...value }
                    : value
            )
        ),
        delete: vi.fn((ref) => documents.delete(ref.path))
    };
    const firestore = {
        writePhoto: vi.fn().mockResolvedValue({ error: null, data: undefined }),
        doc: vi.fn((path: string) => ({
            path,
            set: vi.fn(async (value, options) => {
                const { error } = await firestore.writePhoto(value, options);
                if (error) {
                    return { error, data: null };
                }
                documents.set(path, { ...documents.get(path), ...value });
                return { error: null, data: undefined };
            }),
            get: vi.fn(async () => ({ error: null, data: snapshot({ path }) }))
        })),
        runTransaction: vi.fn(async (operation) => {
            try {
                const data = await operation(transaction);
                return { error: null, data };
            } catch (error) {
                return { error, data: null };
            }
        })
    };
    const adminAuth = {
        updateUser: vi.fn().mockResolvedValue({ error: null, data: {} }),
        getUser: vi.fn().mockResolvedValue({
            error: null,
            data: { localId: 'user', customAttributes: '{"role":"member"}' }
        }),
        setCustomUserClaims: vi
            .fn()
            .mockResolvedValue({ error: null, data: undefined })
    };
    const storage = {
        download: vi.fn().mockResolvedValue({
            error: null,
            data: new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])
        }),
        updateMetadata: vi.fn().mockResolvedValue({ error: null, data: {} }),
        downloadURL: vi.fn().mockResolvedValue({
            error: null,
            data: 'https://firebasestorage.googleapis.com/v0/b/photos-bucket/o/profile-photos%2Fuser%2Fnew?alt=media&token=abc'
        }),
        bucketName: 'photos-bucket',
        getMetadata: vi.fn().mockResolvedValue({
            error: null,
            data: {
                generation: '123',
                metageneration: '1',
                size: '100',
                contentType: 'image/png'
            }
        }),
        delete: vi.fn().mockResolvedValue({ error: null, data: undefined }),
        createResumableUpload: vi.fn().mockResolvedValue({
            error: null,
            data: 'https://example.com/resumable-session'
        }),
        getSignedUrl: vi.fn().mockResolvedValue({
            error: null,
            data: 'https://example.com/signed-upload'
        })
    };
    const profiles = new Profiles(
        firestore as unknown as Firestore,
        adminAuth as unknown as FirebaseAdminAuth,
        path,
        usersCollection,
        storage as unknown as Storage,
        profilePhotosPath,
        profilePhotoMaxBytes
    );
    return { profiles, documents, firestore, transaction, adminAuth, storage };
}

describe('Profiles', () => {
    it('defaults to usernames and accepts subcollections', () => {
        expect(setup().profiles.usernamesCollection).toBe('usernames');
        expect(setup().profiles.usersCollection).toBe('users');
        expect(setup('apps/main/names').profiles.usernamesCollection).toBe(
            'apps/main/names'
        );
    });

    it.each(['', '/users', 'apps/main', 'apps//users'])(
        'rejects invalid users collection path %s',
        (path) => {
            expect(() => setup('usernames', path)).toThrow();
        }
    );

    it('rejects sharing a collection with username reservations', () => {
        expect(() => setup('names', 'names')).toThrow('different collections');
    });

    it('creates and merges usernames in the configured user document', async () => {
        const { profiles, documents, transaction } = setup(
            'names',
            'apps/main/users'
        );
        const { error: createError } = await profiles.updateUsername(
            'user',
            'Alice'
        );
        expect(createError).toBeNull();
        expect(documents.get('apps/main/users/user')).toEqual({
            username: 'alice'
        });

        documents.set('apps/main/users/user', {
            username: 'alice',
            displayName: 'Alice Smith'
        });
        const { error } = await profiles.updateUsername('user', 'Bobby');
        expect(error).toBeNull();
        expect(documents.get('apps/main/users/user')).toEqual({
            username: 'bobby',
            displayName: 'Alice Smith'
        });
        expect(transaction.set).toHaveBeenCalledWith(
            expect.objectContaining({ path: 'apps/main/users/user' }),
            { username: 'bobby' },
            { merge: true }
        );
    });

    it.each(['', '/names', 'apps/main', 'apps//names'])(
        'rejects invalid collection path %s',
        (path) => {
            expect(() => setup(path)).toThrow();
        }
    );

    it.each(['ab', 'a/b', 'hello world', '__bad__/', 'a'.repeat(31), null])(
        'rejects invalid username %s without accessing Firestore',
        async (username) => {
            const { profiles, firestore } = setup();
            const checked = await profiles.checkUsername(username as string);
            const updated = await profiles.updateUsername(
                'user',
                username as string
            );
            expect(checked.error).toMatchObject({
                code: 'profiles/invalid-username'
            });
            expect(updated.error).toMatchObject({
                code: 'profiles/invalid-username'
            });
            expect(firestore.doc).not.toHaveBeenCalled();
        }
    );

    it('checks availability case-insensitively', async () => {
        const { profiles, documents } = setup();
        const available = await profiles.checkUsername('Alice');
        expect(available).toEqual({ error: null, data: true });
        documents.set('usernames/alice', { uid: 'other' });
        const taken = await profiles.checkUsername('ALICE');
        expect(taken).toEqual({ error: null, data: false });
    });

    it('claims, repeats, and renames a username atomically', async () => {
        const { profiles, documents, firestore } = setup('apps/main/names');
        const first = await profiles.updateUsername('user/id', 'Alice');
        expect(first).toEqual({
            error: null,
            data: { uid: 'user/id', username: 'alice' }
        });
        const repeated = await profiles.updateUsername('user/id', 'ALICE');
        expect(repeated.error).toBeNull();
        const renamed = await profiles.updateUsername('user/id', 'Bobby');
        expect(renamed.error).toBeNull();
        expect(documents.has('apps/main/names/alice')).toBe(false);
        expect(documents.get('apps/main/names/bobby')).toEqual({
            uid: 'user/id'
        });
        expect(documents.get('apps/main/names/uid:user%2Fid')).toEqual({
            username: 'bobby'
        });
        expect(documents.get('users/user%2Fid')).toEqual({ username: 'bobby' });
        expect(firestore.runTransaction).toHaveBeenCalledTimes(3);
    });

    it('rejects another owner without writing', async () => {
        const { profiles, documents, transaction } = setup();
        documents.set('usernames/alice', { uid: 'other' });
        const { error } = await profiles.updateUsername('user', 'Alice');
        expect(error).toMatchObject({ code: 'profiles/username-taken' });
        expect(transaction.set).not.toHaveBeenCalled();
        expect(transaction.delete).not.toHaveBeenCalled();
    });

    it.each(['', 'a'.repeat(129), null])(
        'rejects invalid uid %s',
        async (uid) => {
            const { profiles, firestore } = setup();
            const { error } = await profiles.updateUsername(
                uid as string,
                'Alice'
            );
            expect(error).toBeInstanceOf(Error);
            expect(firestore.runTransaction).not.toHaveBeenCalled();
        }
    );

    it('propagates transaction read errors without writing', async () => {
        const { profiles, transaction } = setup();
        const failure = new Error('unavailable');
        transaction.get.mockResolvedValueOnce({
            error: failure,
            data: null
        } as never);
        const { error } = await profiles.updateUsername('user', 'Alice');
        expect(error).toBe(failure);
        expect(transaction.set).not.toHaveBeenCalled();
    });

    it('does not delete a previous reservation belonging to someone else', async () => {
        const { profiles, documents, transaction } = setup();
        documents.set('usernames/uid:user', { username: 'alice' });
        documents.set('usernames/alice', { uid: 'other' });
        const { error } = await profiles.updateUsername('user', 'Bobby');
        expect(error).toBeNull();
        expect(transaction.delete).not.toHaveBeenCalled();
    });
});

it('sets the canonical username claim after commit while preserving existing claims', async () => {
    const { profiles, adminAuth, firestore } = setup();
    const { error } = await profiles.updateUsername('user', 'Alice');
    expect(error).toBeNull();
    expect(adminAuth.getUser).toHaveBeenCalledWith('user');
    expect(adminAuth.setCustomUserClaims).toHaveBeenCalledWith('user', {
        role: 'member',
        username: 'alice'
    });
    expect(
        adminAuth.setCustomUserClaims.mock.invocationCallOrder[0]
    ).toBeGreaterThan(firestore.runTransaction.mock.invocationCallOrder[0]!);
});

it('does not set claims when the transaction fails', async () => {
    const { profiles, documents, adminAuth } = setup();
    documents.set('usernames/alice', { uid: 'other' });
    const { error } = await profiles.updateUsername('user', 'Alice');
    expect(error).toBeInstanceOf(Error);
    expect(adminAuth.setCustomUserClaims).not.toHaveBeenCalled();
});

it.each([new Error('lookup failed'), null])(
    'rejects a failed or missing Auth user before committing',
    async (failure) => {
        const { profiles, adminAuth, firestore } = setup();
        adminAuth.getUser.mockResolvedValueOnce({ error: failure, data: null });
        const { error } = await profiles.updateUsername('user', 'Alice');
        expect(error).toBeInstanceOf(Error);
        expect(firestore.runTransaction).not.toHaveBeenCalled();
        expect(adminAuth.setCustomUserClaims).not.toHaveBeenCalled();
    }
);

it('returns claim errors and repairs the claim on a same-name retry', async () => {
    const { profiles, adminAuth, documents } = setup();
    const failure = new Error('claim failed');
    adminAuth.setCustomUserClaims.mockResolvedValueOnce({
        error: failure,
        data: null
    });
    const { error } = await profiles.updateUsername('user', 'Alice');
    expect(error).toBe(failure);
    expect(documents.get('users/user')).toEqual({ username: 'alice' });
    const { error: retryError } = await profiles.updateUsername(
        'user',
        'Alice'
    );
    expect(retryError).toBeNull();
    expect(adminAuth.setCustomUserClaims).toHaveBeenCalledTimes(2);
});

it('sets the claim when the user has no existing custom claims', async () => {
    const { profiles, adminAuth } = setup();
    adminAuth.getUser.mockResolvedValueOnce({
        error: null,
        data: { localId: 'user' }
    });
    const { error } = await profiles.updateUsername('user', 'Alice');
    expect(error).toBeNull();
    expect(adminAuth.setCustomUserClaims).toHaveBeenCalledWith('user', {
        username: 'alice'
    });
});

it.each(['update', 'remove'] as const)(
    'writes the %s photo to Auth and the configured user document',
    async (action) => {
        const { profiles, adminAuth, documents, firestore } = setup(
            'names',
            'apps/main/users'
        );
        documents.set('apps/main/users/user%2Fid', {
            displayName: 'Alice',
            photoURL: 'https://example.com/old.jpg'
        });
        const photoURL =
            action === 'update' ? 'https://example.com/new.jpg' : null;
        const { error, data } =
            action === 'update'
                ? await profiles.updatePhoto('user/id', photoURL!)
                : await profiles.removePhoto('user/id');
        expect(error).toBeNull();
        expect(data).toEqual({ uid: 'user/id', photoURL });
        expect(adminAuth.updateUser).toHaveBeenCalledWith('user/id', {
            photoURL
        });
        expect(firestore.writePhoto).toHaveBeenCalledWith(
            { photoURL },
            { merge: true }
        );
        expect(documents.get('apps/main/users/user%2Fid')).toEqual({
            displayName: 'Alice',
            photoURL
        });
    }
);

it('creates the user document when setting a photo', async () => {
    const { profiles, documents } = setup();
    const { error } = await profiles.updatePhoto(
        'user',
        'https://example.com/photo.jpg'
    );
    expect(error).toBeNull();
    expect(documents.get('users/user')).toEqual({
        photoURL: 'https://example.com/photo.jpg'
    });
});

it.each(['', 'invalid-url', null, 123])(
    'rejects invalid photo URL %s without writes',
    async (photoURL) => {
        const { profiles, adminAuth, firestore } = setup();
        const { error } = await profiles.updatePhoto(
            'user',
            photoURL as string
        );
        expect(error).toBeInstanceOf(Error);
        expect(adminAuth.updateUser).not.toHaveBeenCalled();
        expect(firestore.writePhoto).not.toHaveBeenCalled();
    }
);

it.each(['', 'a'.repeat(129), null])(
    'rejects invalid photo uid %s in both methods',
    async (uid) => {
        const { profiles, adminAuth, firestore } = setup();
        const { error: updateError } = await profiles.updatePhoto(
            uid as string,
            'https://example.com/photo.jpg'
        );
        const { error: removeError } = await profiles.removePhoto(
            uid as string
        );
        expect(updateError).toBeInstanceOf(Error);
        expect(removeError).toBeInstanceOf(Error);
        expect(adminAuth.updateUser).not.toHaveBeenCalled();
        expect(firestore.writePhoto).not.toHaveBeenCalled();
    }
);

it.each(['update', 'remove'] as const)(
    'propagates Auth errors for photo %s without writing Firestore',
    async (action) => {
        const { profiles, adminAuth, firestore } = setup();
        const failure = new Error('Auth unavailable');
        adminAuth.updateUser.mockResolvedValueOnce({
            error: failure,
            data: null
        });
        const { error } =
            action === 'update'
                ? await profiles.updatePhoto(
                      'user',
                      'https://example.com/photo.jpg'
                  )
                : await profiles.removePhoto('user');
        expect(error).toBe(failure);
        expect(firestore.writePhoto).not.toHaveBeenCalled();
    }
);

it.each(['update', 'remove'] as const)(
    'returns Firestore errors for photo %s and supports retry',
    async (action) => {
        const { profiles, firestore } = setup();
        const failure = new Error('Firestore unavailable');
        firestore.writePhoto.mockResolvedValueOnce({
            error: failure,
            data: null
        });
        const { error } =
            action === 'update'
                ? await profiles.updatePhoto(
                      'user',
                      'https://example.com/photo.jpg'
                  )
                : await profiles.removePhoto('user');
        expect(error).toBe(failure);
        const { error: retryError } =
            action === 'update'
                ? await profiles.updatePhoto(
                      'user',
                      'https://example.com/photo.jpg'
                  )
                : await profiles.removePhoto('user');
        expect(retryError).toBeNull();
    }
);

it('creates a signed photo PUT URL with defaults without modifying profiles', async () => {
    const { profiles, storage, adminAuth, firestore } = setup();
    const { error, data } = await profiles.createPhotoUploadUrl('user/id');
    expect(error).toBeNull();
    expect(data).toEqual({
        uploadUrl: 'https://example.com/signed-upload',
        path: expect.stringMatching(/^profile-photos\/user%2Fid\/[a-f0-9-]+$/),
        contentType: 'image/jpeg',
        headers: {
            'Content-Type': 'image/jpeg',
            'x-goog-content-length-range': '0,8388608'
        },
        maxBytes: 8388608
    });
    expect(storage.getSignedUrl).toHaveBeenCalledWith(data?.path, {
        action: 'write',
        contentType: 'image/jpeg',
        expiresInSeconds: 900,
        maxBytes: 8388608
    });
    expect(adminAuth.updateUser).not.toHaveBeenCalled();
    expect(firestore.doc).not.toHaveBeenCalled();
});

it('uses unique object paths and forwards upload options', async () => {
    const { profiles, storage } = setup();
    const { data: first } = await profiles.createPhotoUploadUrl('user', {
        contentType: 'image/webp',
        expiresInSeconds: 60
    });
    const { data: second } = await profiles.createPhotoUploadUrl('user');
    expect(first?.path).not.toBe(second?.path);
    expect(storage.getSignedUrl).toHaveBeenNthCalledWith(1, first?.path, {
        action: 'write',
        contentType: 'image/webp',
        expiresInSeconds: 60,
        maxBytes: 8388608
    });
});

it.each(['', 'a'.repeat(129), null])(
    'rejects invalid upload uid %s',
    async (uid) => {
        const { profiles, storage } = setup();
        const { error } = await profiles.createPhotoUploadUrl(uid as string);
        expect(error).toBeInstanceOf(Error);
        expect(storage.getSignedUrl).not.toHaveBeenCalled();
    }
);

it.each([null, [], 'bad'])(
    'rejects invalid upload options %s',
    async (options) => {
        const { profiles, storage } = setup();
        const { error } = await profiles.createPhotoUploadUrl(
            'user',
            options as never
        );
        expect(error).toMatchObject({
            code: 'profiles/invalid-upload-options'
        });
        expect(storage.getSignedUrl).not.toHaveBeenCalled();
    }
);

it.each(['text/plain', 'image/svg+xml', '', 'image/png\r\nBad: value'])(
    'rejects unsupported photo type %s',
    async (contentType) => {
        const { profiles, storage } = setup();
        const { error } = await profiles.createPhotoUploadUrl('user', {
            contentType: contentType as never
        });
        expect(error).toMatchObject({ code: 'profiles/invalid-photo-type' });
        expect(storage.getSignedUrl).not.toHaveBeenCalled();
    }
);

it('returns an error when standalone Profiles has no Storage', async () => {
    const { firestore, adminAuth } = setup();
    const profiles = new Profiles(
        firestore as unknown as Firestore,
        adminAuth as unknown as FirebaseAdminAuth
    );
    const { error } = await profiles.createPhotoUploadUrl('user');
    expect(error).toMatchObject({ code: 'profiles/storage-required' });
});

it('propagates signing failures', async () => {
    const { profiles, storage } = setup();
    const failure = new Error('Signing failed');
    storage.getSignedUrl.mockResolvedValueOnce({ error: failure, data: null });
    const { error } = await profiles.createPhotoUploadUrl('user');
    expect(error).toBe(failure);
});

it('uses the default profile photo prefix', () => {
    expect(setup().profiles.profilePhotosPath).toBe('profile-photos');
});

it('signs photo uploads under a configured nested prefix', async () => {
    const { profiles, storage } = setup(
        'usernames',
        'users',
        'apps/main/photos'
    );
    const { error, data } = await profiles.createPhotoUploadUrl('user');
    expect(error).toBeNull();
    expect(data?.path).toMatch(/^apps\/main\/photos\/user\/[a-f0-9-]+$/);
    expect(storage.getSignedUrl).toHaveBeenCalledWith(data?.path, {
        action: 'write',
        contentType: 'image/jpeg',
        expiresInSeconds: 900,
        maxBytes: 8388608
    });
});

it.each([
    '',
    ' ',
    '/photos',
    'photos/',
    'photos//nested',
    '.',
    '..',
    'photos/../nested',
    'photos/./nested',
    'photos\\nested',
    'photos\n',
    null
])('rejects invalid profile photo prefix %s', (path) => {
    expect(() => setup('usernames', 'users', path as string)).toThrow(
        'Profile photos path'
    );
});

it.each([1, 1024, null])(
    'applies configured photo byte limit %s',
    async (maxBytes) => {
        const { profiles, storage } = setup(
            'usernames',
            'users',
            'profile-photos',
            maxBytes
        );
        const { error, data } = await profiles.createPhotoUploadUrl('user');
        expect(error).toBeNull();
        expect(data?.maxBytes).toBe(maxBytes);
        expect(data?.headers).toEqual(
            maxBytes === null
                ? { 'Content-Type': 'image/jpeg' }
                : {
                      'Content-Type': 'image/jpeg',
                      'x-goog-content-length-range': `0,${maxBytes}`
                  }
        );
        expect(storage.getSignedUrl).toHaveBeenCalledWith(data?.path, {
            action: 'write',
            contentType: 'image/jpeg',
            expiresInSeconds: 900,
            maxBytes: maxBytes ?? undefined
        });
    }
);

it.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1024'])(
    'rejects invalid photo size limit %s',
    (maxBytes) => {
        expect(() =>
            setup('usernames', 'users', undefined, maxBytes as number)
        ).toThrow('positive safe integer or null');
    }
);

it.each(['Alice Smith', '', null])(
    'updates displayName %s in Auth and the configured user doc',
    async (displayName) => {
        const { profiles, adminAuth, documents, firestore } = setup(
            'names',
            'apps/main/users'
        );
        documents.set('apps/main/users/user', {
            photoURL: 'https://example.com/photo.jpg',
            username: 'alice'
        });
        const { error, data } = await profiles.updateDisplayName(
            'user',
            displayName
        );
        expect(error).toBeNull();
        expect(data).toEqual({ uid: 'user', displayName });
        expect(adminAuth.updateUser).toHaveBeenCalledWith('user', {
            displayName
        });
        expect(firestore.writePhoto).toHaveBeenCalledWith(
            { displayName },
            { merge: true }
        );
        expect(documents.get('apps/main/users/user')).toEqual({
            displayName,
            photoURL: 'https://example.com/photo.jpg',
            username: 'alice'
        });
    }
);

it.each([
    { displayName: 'Alice', photoURL: 'https://example.com/new.jpg' },
    { displayName: 'Alice' },
    { photoURL: 'https://example.com/new.jpg' },
    { displayName: null, photoURL: null },
    { displayName: 'Alice', photoURL: undefined }
])('merges supplied profile fields in both services: %j', async (updates) => {
    const { profiles, adminAuth, documents, firestore } = setup();
    documents.set('users/user', { username: 'alice' });
    const { error, data } = await profiles.updateProfile('user', updates);
    const fields = Object.fromEntries(
        Object.entries(updates).filter(([, value]) => value !== undefined)
    );
    expect(error).toBeNull();
    expect(data).toEqual({ uid: 'user', ...fields });
    expect(adminAuth.updateUser).toHaveBeenCalledExactlyOnceWith(
        'user',
        fields
    );
    expect(firestore.writePhoto).toHaveBeenCalledExactlyOnceWith(fields, {
        merge: true
    });
    expect(documents.get('users/user')).toEqual({
        username: 'alice',
        ...fields
    });
});

it('creates a missing user document through updateProfile', async () => {
    const { profiles, documents } = setup();
    const { error } = await profiles.updateProfile('user', {
        displayName: 'Alice'
    });
    expect(error).toBeNull();
    expect(documents.get('users/user')).toEqual({ displayName: 'Alice' });
});

it.each([
    null,
    [],
    {},
    { displayName: undefined },
    { username: 'alice' },
    { displayName: 123 },
    { photoURL: '' },
    { photoURL: 'invalid-url' }
])('rejects invalid profile updates before writes: %j', async (updates) => {
    const { profiles, adminAuth, firestore } = setup();
    const { error } = await profiles.updateProfile('user', updates as never);
    expect(error).toBeInstanceOf(Error);
    expect(adminAuth.updateUser).not.toHaveBeenCalled();
    expect(firestore.writePhoto).not.toHaveBeenCalled();
});

it.each([123, undefined, {}])(
    'rejects invalid displayName %j without writes',
    async (displayName) => {
        const { profiles, adminAuth } = setup();
        const { error } = await profiles.updateDisplayName(
            'user',
            displayName as never
        );
        expect(error).toBeInstanceOf(Error);
        expect(adminAuth.updateUser).not.toHaveBeenCalled();
    }
);

it.each(['', 'a'.repeat(129), null])(
    'rejects invalid uid %s in new profile methods',
    async (uid) => {
        const { profiles, adminAuth } = setup();
        const { error: nameError } = await profiles.updateDisplayName(
            uid as string,
            'Alice'
        );
        const { error: profileError } = await profiles.updateProfile(
            uid as string,
            { displayName: 'Alice' }
        );
        expect(nameError).toBeInstanceOf(Error);
        expect(profileError).toBeInstanceOf(Error);
        expect(adminAuth.updateUser).not.toHaveBeenCalled();
    }
);

it.each(['name', 'profile'] as const)(
    'propagates Auth errors for %s without Firestore writes',
    async (method) => {
        const { profiles, adminAuth, firestore } = setup();
        const failure = new Error('Auth failed');
        adminAuth.updateUser.mockResolvedValueOnce({
            error: failure,
            data: null
        });
        const { error } =
            method === 'name'
                ? await profiles.updateDisplayName('user', 'Alice')
                : await profiles.updateProfile('user', {
                      displayName: 'Alice',
                      photoURL: null
                  });
        expect(error).toBe(failure);
        expect(firestore.writePhoto).not.toHaveBeenCalled();
    }
);

it.each(['name', 'profile'] as const)(
    'returns Firestore errors and supports retry for %s',
    async (method) => {
        const { profiles, firestore } = setup();
        const failure = new Error('Firestore failed');
        firestore.writePhoto.mockResolvedValueOnce({
            error: failure,
            data: null
        });
        const { error } =
            method === 'name'
                ? await profiles.updateDisplayName('user', 'Alice')
                : await profiles.updateProfile('user', {
                      displayName: 'Alice',
                      photoURL: null
                  });
        expect(error).toBe(failure);
        const { error: retryError } =
            method === 'name'
                ? await profiles.updateDisplayName('user', 'Alice')
                : await profiles.updateProfile('user', {
                      displayName: 'Alice',
                      photoURL: null
                  });
        expect(retryError).toBeNull();
    }
);

it('creates a resumable photo session using configured storage and path', async () => {
    const { profiles, storage, adminAuth, firestore } = setup(
        'names',
        'users',
        'custom/photos'
    );
    const { error, data } = await profiles.createResumablePhotoUploadUrl(
        'user/id',
        {
            size: 1024,
            contentType: 'image/png',
            origin: 'https://app.example.com'
        }
    );
    expect(error).toBeNull();
    expect(data).toEqual({
        uploadUrl: 'https://example.com/resumable-session',
        path: expect.stringMatching(/^custom\/photos\/user%2Fid\/[a-f0-9-]+$/),
        contentType: 'image/png',
        size: 1024,
        maxBytes: 8388608
    });
    expect(storage.createResumableUpload).toHaveBeenCalledWith(data?.path, {
        size: 1024,
        contentType: 'image/png',
        origin: 'https://app.example.com'
    });
    expect(storage.getSignedUrl).not.toHaveBeenCalled();
    expect(adminAuth.updateUser).not.toHaveBeenCalled();
    expect(firestore.doc).not.toHaveBeenCalled();
});

it('defaults resumable content type and accepts exactly the size cap', async () => {
    const { profiles, storage } = setup();
    const { error, data } = await profiles.createResumablePhotoUploadUrl(
        'user',
        { size: 8388608 }
    );
    expect(error).toBeNull();
    expect(storage.createResumableUpload).toHaveBeenCalledWith(data?.path, {
        size: 8388608,
        contentType: 'image/jpeg',
        origin: undefined
    });
});

it('rejects a resumable photo larger than the custom cap before creating a session', async () => {
    const { profiles, storage } = setup('names', 'users', 'photos', 1024);
    const { error } = await profiles.createResumablePhotoUploadUrl('user', {
        size: 1025
    });
    expect(error).toMatchObject({ code: 'profiles/photo-too-large' });
    expect(storage.createResumableUpload).not.toHaveBeenCalled();
});

it('allows larger resumable photos when the application cap is disabled', async () => {
    const { profiles } = setup('names', 'users', 'photos', null);
    const { error, data } = await profiles.createResumablePhotoUploadUrl(
        'user',
        { size: 8388609 }
    );
    expect(error).toBeNull();
    expect(data?.maxBytes).toBeNull();
});

it.each([
    undefined,
    0,
    -1,
    1.5,
    Infinity,
    NaN,
    Number.MAX_SAFE_INTEGER + 1,
    '1024'
])('rejects invalid resumable photo size %s', async (size) => {
    const { profiles, storage } = setup();
    const { error } = await profiles.createResumablePhotoUploadUrl('user', {
        size: size as number
    });
    expect(error).toMatchObject({ code: 'profiles/invalid-photo-size' });
    expect(storage.createResumableUpload).not.toHaveBeenCalled();
});

it.each([null, undefined, [], 'bad'])(
    'rejects invalid resumable options %j',
    async (options) => {
        const { profiles, storage } = setup();
        const { error } = await profiles.createResumablePhotoUploadUrl(
            'user',
            options as never
        );
        expect(error).toMatchObject({
            code: 'profiles/invalid-upload-options'
        });
        expect(storage.createResumableUpload).not.toHaveBeenCalled();
    }
);

it.each(['', 'a'.repeat(129), null])(
    'rejects invalid resumable UID %s',
    async (uid) => {
        const { profiles, storage } = setup();
        const { error } = await profiles.createResumablePhotoUploadUrl(
            uid as string,
            { size: 1024 }
        );
        expect(error).toBeInstanceOf(Error);
        expect(storage.createResumableUpload).not.toHaveBeenCalled();
    }
);

it('rejects invalid resumable photo types', async () => {
    const { profiles, storage } = setup();
    const { error } = await profiles.createResumablePhotoUploadUrl('user', {
        size: 1024,
        contentType: 'text/plain' as never
    });
    expect(error).toMatchObject({ code: 'profiles/invalid-photo-type' });
    expect(storage.createResumableUpload).not.toHaveBeenCalled();
});

it('requires Storage for resumable photos', async () => {
    const { firestore, adminAuth } = setup();
    const profiles = new Profiles(
        firestore as unknown as Firestore,
        adminAuth as unknown as FirebaseAdminAuth
    );
    const { error } = await profiles.createResumablePhotoUploadUrl('user', {
        size: 1024
    });
    expect(error).toMatchObject({ code: 'profiles/storage-required' });
});

it('propagates resumable session errors', async () => {
    const { profiles, storage } = setup();
    const failure = new Error('Cannot create session');
    storage.createResumableUpload.mockResolvedValueOnce({
        error: failure,
        data: null
    });
    const { error } = await profiles.createResumablePhotoUploadUrl('user', {
        size: 1024
    });
    expect(error).toBe(failure);
});

it.each(['remove', 'update', 'profile'] as const)(
    'deletes old managed photos after %s succeeds',
    async (action) => {
        const { profiles, documents, adminAuth, storage, firestore } = setup();
        const oldURL =
            'https://storage.googleapis.com/photos-bucket/profile-photos/user/old';
        documents.set('users/user', { photoURL: oldURL, displayName: 'Alice' });
        adminAuth.getUser.mockResolvedValueOnce({
            error: null,
            data: { localId: 'user', photoUrl: oldURL }
        });
        const newURL =
            'https://storage.googleapis.com/photos-bucket/profile-photos/user/new';
        const { error } =
            action === 'remove'
                ? await profiles.removePhoto('user')
                : action === 'update'
                  ? await profiles.updatePhoto('user', newURL)
                  : await profiles.updateProfile('user', {
                        displayName: 'Bob',
                        photoURL: newURL
                    });
        expect(error).toBeNull();
        expect(storage.delete).toHaveBeenCalledExactlyOnceWith(
            'profile-photos/user/old',
            { ifGenerationMatch: '123' }
        );
        expect(storage.delete.mock.invocationCallOrder[0]!).toBeGreaterThan(
            firestore.writePhoto.mock.invocationCallOrder[0]!
        );
        expect(documents.get('users/user')?.photoURL).toBe(
            action === 'remove' ? null : newURL
        );
    }
);

it('deletes differing Auth and Firestore photos using the configured prefix', async () => {
    const { profiles, documents, adminAuth, storage } = setup(
        'names',
        'apps/main/users',
        'custom/photos'
    );
    documents.set('apps/main/users/user', {
        photoURL:
            'https://firebasestorage.googleapis.com/v0/b/photos-bucket/o/custom%2Fphotos%2Fuser%2Ffirst?alt=media'
    });
    adminAuth.getUser.mockResolvedValueOnce({
        error: null,
        data: {
            localId: 'user',
            photoUrl:
                'https://storage.googleapis.com/photos-bucket/custom/photos/user/second'
        }
    });
    const { error } = await profiles.removePhoto('user');
    expect(error).toBeNull();
    expect(storage.delete).toHaveBeenCalledTimes(2);
    expect(storage.delete).toHaveBeenCalledWith('custom/photos/user/first', {
        ifGenerationMatch: '123'
    });
    expect(storage.delete).toHaveBeenCalledWith('custom/photos/user/second', {
        ifGenerationMatch: '123'
    });
});

it.each(['update', 'profile'] as const)(
    'keeps the old photo when requested through %s',
    async (method) => {
        const { profiles, documents, storage, adminAuth } = setup();
        documents.set('users/user', {
            photoURL:
                'https://storage.googleapis.com/photos-bucket/profile-photos/user/old'
        });
        const { error } =
            method === 'update'
                ? await profiles.updatePhoto(
                      'user',
                      'https://example.com/new',
                      { keepOldPhoto: true }
                  )
                : await profiles.updateProfile(
                      'user',
                      { photoURL: 'https://example.com/new' },
                      { keepOldPhoto: true }
                  );
        expect(error).toBeNull();
        expect(storage.delete).not.toHaveBeenCalled();
        expect(adminAuth.getUser).not.toHaveBeenCalled();
    }
);

it('keeps the same storage object when only its URL token changes', async () => {
    const { profiles, documents, storage } = setup();
    documents.set('users/user', {
        photoURL:
            'https://storage.googleapis.com/photos-bucket/profile-photos/user/same?token=old'
    });
    const { error } = await profiles.updatePhoto(
        'user',
        'https://firebasestorage.googleapis.com/v0/b/photos-bucket/o/profile-photos%2Fuser%2Fsame?token=new'
    );
    expect(error).toBeNull();
    expect(storage.delete).not.toHaveBeenCalled();
});

it.each([
    'https://example.com/photo',
    'https://storage.googleapis.com/other/profile-photos/user/old',
    'https://storage.googleapis.com/photos-bucket/profile-photos/other/old'
])(
    'clears unmanaged photo references without deleting %s',
    async (photoURL) => {
        const { profiles, documents, storage } = setup();
        documents.set('users/user', { photoURL });
        const { error } = await profiles.removePhoto('user');
        expect(error).toBeNull();
        expect(storage.delete).not.toHaveBeenCalled();
    }
);

it('does not delete if the profile write fails', async () => {
    const { profiles, documents, firestore, storage } = setup();
    documents.set('users/user', {
        photoURL:
            'https://storage.googleapis.com/photos-bucket/profile-photos/user/old'
    });
    firestore.writePhoto.mockResolvedValueOnce({
        error: new Error('write failed'),
        data: null
    });
    const { error } = await profiles.removePhoto('user');
    expect(error).toBeInstanceOf(Error);
    expect(storage.delete).not.toHaveBeenCalled();
});

it.each(['metadata', 'delete'] as const)(
    'ignores missing old objects during %s',
    async (stage) => {
        const { profiles, documents, storage } = setup();
        documents.set('users/user', {
            photoURL:
                'https://storage.googleapis.com/photos-bucket/profile-photos/user/old'
        });
        const missing = Object.assign(new Error('missing'), {
            code: 'storage/object-not-found'
        });
        (stage === 'metadata'
            ? storage.getMetadata
            : storage.delete
        ).mockResolvedValueOnce({ error: missing, data: null });
        const { error } = await profiles.removePhoto('user');
        expect(error).toBeNull();
    }
);

it('returns cleanup errors with the remaining object path after the profile is updated', async () => {
    const { profiles, documents, storage } = setup();
    documents.set('users/user', {
        photoURL:
            'https://storage.googleapis.com/photos-bucket/profile-photos/user/old'
    });
    storage.delete.mockResolvedValueOnce({
        error: new Error('denied'),
        data: null
    });
    const { error } = await profiles.removePhoto('user');
    expect(error).toMatchObject({
        code: 'profiles/photo-cleanup-failed',
        context: { path: 'profile-photos/user/old' }
    });
    expect(documents.get('users/user')?.photoURL).toBeNull();
});

it.each([null, [], { keepOldPhoto: 'yes' }])(
    'rejects invalid cleanup options %j before writes',
    async (options) => {
        const { profiles, adminAuth } = setup();
        const { error } = await profiles.updatePhoto(
            'user',
            'https://example.com/photo',
            options as never
        );
        expect(error).toMatchObject({ code: 'profiles/invalid-photo-options' });
        expect(adminAuth.updateUser).not.toHaveBeenCalled();
    }
);

it('reports metadata cleanup failures with the remaining path', async () => {
    const { profiles, documents, storage } = setup();
    documents.set('users/user', {
        photoURL:
            'https://storage.googleapis.com/photos-bucket/profile-photos/user/old'
    });
    storage.getMetadata.mockResolvedValueOnce({
        error: new Error('metadata denied'),
        data: null
    });
    const { error } = await profiles.removePhoto('user');
    expect(error).toMatchObject({
        code: 'profiles/photo-cleanup-failed',
        context: { path: 'profile-photos/user/old' }
    });
    expect(storage.delete).not.toHaveBeenCalled();
});

it.each([new Error('lookup failed'), null])(
    'stops before writes when the old Auth profile cannot be read (%s)',
    async (failure) => {
        const { profiles, adminAuth, storage, firestore } = setup();
        adminAuth.getUser.mockResolvedValueOnce({ error: failure, data: null });
        const { error } = await profiles.removePhoto('user');
        expect(error).toBeInstanceOf(Error);
        expect(adminAuth.updateUser).not.toHaveBeenCalled();
        expect(firestore.writePhoto).not.toHaveBeenCalled();
        expect(storage.delete).not.toHaveBeenCalled();
    }
);

it('does not read or delete photos for a display-name-only update', async () => {
    const { profiles, adminAuth, storage } = setup();
    const { error } = await profiles.updateDisplayName('user', 'Alice');
    expect(error).toBeNull();
    expect(adminAuth.getUser).not.toHaveBeenCalled();
    expect(storage.getMetadata).not.toHaveBeenCalled();
    expect(storage.delete).not.toHaveBeenCalled();
});

it('reads the configured profile document and returns null when missing', async () => {
    const { profiles, documents } = setup('names', 'apps/main/users');
    const { error, data: missing } = await profiles.getProfile('user/id');
    expect(error).toBeNull();
    expect(missing).toBeNull();
    documents.set('apps/main/users/user%2Fid', {
        displayName: 'Alice',
        username: 'alice'
    });
    const { data } = await profiles.getProfile('user/id');
    expect(data).toEqual({ displayName: 'Alice', username: 'alice' });
});

it.each(['', null, 'a'.repeat(129)])(
    'validates UID %s in all new methods',
    async (uid) => {
        const { profiles, firestore, storage, adminAuth } = setup();
        const results = [
            await profiles.getProfile(uid as string),
            await profiles.completePhotoUpload(
                uid as string,
                'profile-photos/user/new'
            ),
            await profiles.removeUsername(uid as string)
        ];
        for (const { error } of results) expect(error).toBeInstanceOf(Error);
        expect(firestore.doc).not.toHaveBeenCalled();
        expect(storage.getMetadata).not.toHaveBeenCalled();
        expect(adminAuth.getUser).not.toHaveBeenCalled();
    }
);

it('propagates profile read failures', async () => {
    const { profiles, firestore } = setup();
    const failure = new Error('read failed');
    firestore.doc.mockReturnValueOnce({
        get: vi.fn().mockResolvedValue({ error: failure, data: null })
    } as never);
    const { error } = await profiles.getProfile('user');
    expect(error).toBe(failure);
});

it('verifies and completes an uploaded photo through existing Storage and profile APIs', async () => {
    const { profiles, storage, documents } = setup();
    const { error, data } = await profiles.completePhotoUpload(
        'user',
        'profile-photos/user/new'
    );
    expect(error).toBeNull();
    expect(storage.download).toHaveBeenCalledWith('profile-photos/user/new', {
        start: 0,
        end: 15,
        generation: '123'
    });
    expect(storage.updateMetadata).toHaveBeenCalledWith(
        'profile-photos/user/new',
        { metadata: { firebaseStorageDownloadTokens: expect.any(String) } },
        { ifGenerationMatch: '123', ifMetagenerationMatch: '1' }
    );
    expect(documents.get('users/user')?.photoURL).toBe(data?.photoURL);
    expect(data?.photoURL).toContain('token=abc');
});

it('preserves existing download tokens and metadata', async () => {
    const { profiles, storage } = setup();
    storage.getMetadata.mockResolvedValueOnce({
        error: null,
        data: {
            generation: '123',
            metageneration: '1',
            size: '100',
            contentType: 'image/png',
            metadata: {
                firebaseStorageDownloadTokens: 'existing',
                custom: 'keep'
            }
        }
    });
    const { error } = await profiles.completePhotoUpload(
        'user',
        'profile-photos/user/new'
    );
    expect(error).toBeNull();
    expect(storage.updateMetadata).toHaveBeenCalledWith(
        expect.any(String),
        {
            metadata: {
                firebaseStorageDownloadTokens: 'existing',
                custom: 'keep'
            }
        },
        expect.any(Object)
    );
});

it.each([
    'other/user/new',
    'profile-photos/other/new',
    'profile-photos/user/../new',
    '',
    null
])('rejects an unowned completion path %s', async (path) => {
    const { profiles, storage } = setup();
    const { error } = await profiles.completePhotoUpload(
        'user',
        path as string
    );
    expect(error).toMatchObject({ code: 'profiles/invalid-photo-path' });
    expect(storage.getMetadata).not.toHaveBeenCalled();
});

it.each([
    {
        size: '0',
        contentType: 'image/png',
        code: 'profiles/invalid-photo-size'
    },
    {
        size: 'oops',
        contentType: 'image/png',
        code: 'profiles/invalid-photo-size'
    },
    {
        size: '8388609',
        contentType: 'image/png',
        code: 'profiles/photo-too-large'
    },
    {
        size: '100',
        contentType: 'text/plain',
        code: 'profiles/invalid-photo-type'
    }
])(
    'rejects invalid stored photo metadata %j',
    async ({ size, contentType, code }) => {
        const { profiles, storage, adminAuth } = setup();
        storage.getMetadata.mockResolvedValueOnce({
            error: null,
            data: { generation: '123', size, contentType }
        });
        const { error } = await profiles.completePhotoUpload(
            'user',
            'profile-photos/user/new'
        );
        expect(error).toMatchObject({ code });
        expect(adminAuth.updateUser).not.toHaveBeenCalled();
        expect(storage.updateMetadata).not.toHaveBeenCalled();
    }
);

it('rejects a mismatching image signature', async () => {
    const { profiles, storage } = setup();
    storage.download.mockResolvedValueOnce({
        error: null,
        data: new Uint8Array([1, 2, 3])
    });
    const { error } = await profiles.completePhotoUpload(
        'user',
        'profile-photos/user/new'
    );
    expect(error).toMatchObject({ code: 'profiles/invalid-photo-type' });
    expect(storage.updateMetadata).not.toHaveBeenCalled();
});

it.each(['getMetadata', 'download', 'updateMetadata', 'downloadURL'] as const)(
    'propagates completion %s failures',
    async (method) => {
        const { profiles, storage, adminAuth } = setup();
        const failure = new Error('Storage failed');
        storage[method].mockResolvedValueOnce({ error: failure, data: null });
        const { error } = await profiles.completePhotoUpload(
            'user',
            'profile-photos/user/new'
        );
        expect(error).toBe(failure);
        expect(adminAuth.updateUser).not.toHaveBeenCalled();
    }
);

it('supports a custom completion path and disabled size cap', async () => {
    const { profiles, storage } = setup(
        'names',
        'users',
        'custom/photos',
        null
    );
    storage.getMetadata.mockResolvedValueOnce({
        error: null,
        data: { generation: '123', size: '8388609', contentType: 'image/png' }
    });
    const { error } = await profiles.completePhotoUpload(
        'user',
        'custom/photos/user/new'
    );
    expect(error).toBeNull();
    expect(storage.getMetadata).toHaveBeenCalledWith('custom/photos/user/new');
});

it('requires Storage for completion', async () => {
    const { firestore, adminAuth } = setup();
    const profiles = new Profiles(
        firestore as unknown as Firestore,
        adminAuth as unknown as FirebaseAdminAuth
    );
    const { error } = await profiles.completePhotoUpload(
        'user',
        'profile-photos/user/new'
    );
    expect(error).toMatchObject({ code: 'profiles/storage-required' });
});

it('removes username reservations and claim while preserving unrelated fields and claims', async () => {
    const { profiles, documents, adminAuth, transaction } = setup(
        'apps/main/names',
        'apps/main/users'
    );
    documents.set('apps/main/names/uid:user', { username: 'alice' });
    documents.set('apps/main/names/alice', { uid: 'user' });
    documents.set('apps/main/users/user', {
        username: 'alice',
        displayName: 'Alice'
    });
    adminAuth.getUser.mockResolvedValueOnce({
        error: null,
        data: {
            localId: 'user',
            customAttributes: '{"username":"alice","role":"admin"}'
        }
    });
    const { error, data } = await profiles.removeUsername('user');
    expect(error).toBeNull();
    expect(data).toEqual({ uid: 'user', username: null });
    expect(documents.has('apps/main/names/alice')).toBe(false);
    expect(documents.has('apps/main/names/uid:user')).toBe(false);
    expect(documents.get('apps/main/users/user')).toEqual({
        username: null,
        displayName: 'Alice'
    });
    expect(adminAuth.setCustomUserClaims).toHaveBeenCalledWith('user', {
        role: 'admin'
    });
    expect(transaction.get.mock.invocationCallOrder.at(-1)!).toBeLessThan(
        transaction.delete.mock.invocationCallOrder[0]!
    );
});

it('does not release another user’s username and can be repeated', async () => {
    const { profiles, documents } = setup();
    documents.set('usernames/uid:user', { username: 'alice' });
    documents.set('usernames/alice', { uid: 'other' });
    const { error } = await profiles.removeUsername('user');
    const { error: repeatError } = await profiles.removeUsername('user');
    expect(error).toBeNull();
    expect(repeatError).toBeNull();
    expect(documents.get('usernames/alice')).toEqual({ uid: 'other' });
});

it('releases a reservation found only in the user document', async () => {
    const { profiles, documents } = setup();
    documents.set('users/user', { username: 'alice' });
    documents.set('usernames/alice', { uid: 'user' });
    const { error } = await profiles.removeUsername('user');
    expect(error).toBeNull();
    expect(documents.has('usernames/alice')).toBe(false);
});

it.each([new Error('lookup failed'), null])(
    'rejects username removal without an Auth user %s',
    async (failure) => {
        const { profiles, adminAuth, firestore } = setup();
        adminAuth.getUser.mockResolvedValueOnce({ error: failure, data: null });
        const { error } = await profiles.removeUsername('user');
        expect(error).toBeInstanceOf(Error);
        expect(firestore.runTransaction).not.toHaveBeenCalled();
    }
);

it('does not clear claims if the removal transaction fails', async () => {
    const { profiles, transaction, adminAuth } = setup();
    const failure = new Error('transaction failed');
    transaction.get.mockResolvedValueOnce({
        error: failure,
        data: null
    } as never);
    const { error } = await profiles.removeUsername('user');
    expect(error).toBe(failure);
    expect(adminAuth.setCustomUserClaims).not.toHaveBeenCalled();
});

it('retries claim removal after a committed Firestore removal', async () => {
    const { profiles, adminAuth } = setup();
    const failure = new Error('claims failed');
    adminAuth.setCustomUserClaims.mockResolvedValueOnce({
        error: failure,
        data: null
    });
    const { error } = await profiles.removeUsername('user');
    const { error: retryError } = await profiles.removeUsername('user');
    expect(error).toBe(failure);
    expect(retryError).toBeNull();
});

it.each([undefined, false])(
    'does not fetch Auth for default or disabled includeAuth %s',
    async (includeAuth) => {
        const { profiles, documents, adminAuth, firestore } = setup();
        documents.set('users/user', { displayName: 'Alice' });
        const { error, data } = await profiles.getProfile('user', {
            includeAuth
        });
        expect(error).toBeNull();
        expect(data).toEqual({ displayName: 'Alice' });
        expect(adminAuth.getUser).not.toHaveBeenCalled();
        expect(firestore.doc).toHaveBeenCalledTimes(1);
    }
);

it('combines selected Auth fields with the configured Firestore profile using Auth precedence', async () => {
    const { profiles, documents, adminAuth } = setup(
        'names',
        'apps/main/users'
    );
    documents.set('apps/main/users/user', {
        uid: 'stale-uid',
        displayName: 'Old name',
        photoURL: 'https://example.com/old',
        username: 'alice',
        theme: 'dark'
    });
    adminAuth.getUser.mockResolvedValueOnce({
        error: null,
        data: {
            localId: 'user',
            displayName: 'Auth name',
            photoUrl: 'https://example.com/auth',
            email: 'private@example.com',
            customAttributes: '{"admin":true}',
            providerUserInfo: [],
            validSince: '123'
        }
    });
    const { error, data } = await profiles.getProfile('user', {
        includeAuth: true
    });
    expect(error).toBeNull();
    expect(data).toEqual({
        uid: 'user',
        displayName: 'Auth name',
        photoURL: 'https://example.com/auth',
        username: 'alice',
        theme: 'dark'
    });
    expect(adminAuth.getUser).toHaveBeenCalledExactlyOnceWith('user');
});

it('returns an Auth-based profile when the Firestore document is missing', async () => {
    const { profiles } = setup();
    const { error, data } = await profiles.getProfile('user', {
        includeAuth: true
    });
    expect(error).toBeNull();
    expect(data).toEqual({ uid: 'user', displayName: null, photoURL: null });
});

it('cleared Auth fields override stale Firestore fields with null', async () => {
    const { profiles, documents } = setup();
    documents.set('users/user', {
        displayName: 'Old',
        photoURL: 'https://example.com/old'
    });
    const { data } = await profiles.getProfile('user', { includeAuth: true });
    expect(data).toEqual({ uid: 'user', displayName: null, photoURL: null });
});

it.each([new Error('Auth failed'), null])(
    'returns an error when combined Auth lookup fails or has no user (%s)',
    async (failure) => {
        const { profiles, adminAuth } = setup();
        adminAuth.getUser.mockResolvedValueOnce({ error: failure, data: null });
        const { error, data } = await profiles.getProfile('user', {
            includeAuth: true
        });
        expect(error).toBeInstanceOf(Error);
        expect(data).toBeNull();
    }
);

it.each([null, [], 'yes', { includeAuth: 'yes' }, { includeAuth: null }])(
    'rejects invalid profile read options %j before reads',
    async (options) => {
        const { profiles, adminAuth, firestore } = setup();
        const { error } = await profiles.getProfile('user', options as never);
        expect(error).toMatchObject({
            code: 'profiles/invalid-profile-options'
        });
        expect(firestore.doc).not.toHaveBeenCalled();
        expect(adminAuth.getUser).not.toHaveBeenCalled();
    }
);

it('propagates Firestore failures without fetching Auth for combined reads', async () => {
    const { profiles, adminAuth, firestore } = setup();
    const failure = new Error('Firestore failed');
    firestore.doc.mockReturnValueOnce({
        get: vi.fn().mockResolvedValue({ error: failure, data: null })
    } as never);
    const { error } = await profiles.getProfile('user', { includeAuth: true });
    expect(error).toBe(failure);
    expect(adminAuth.getUser).not.toHaveBeenCalled();
});
