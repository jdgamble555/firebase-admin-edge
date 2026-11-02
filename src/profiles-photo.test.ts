import { expect, it } from 'vitest';
import { profilePhotoPath } from './profiles-photo.js';

it.each([
    'https://storage.googleapis.com/bucket/photos/user/old?signature=abc',
    'https://firebasestorage.googleapis.com/v0/b/bucket/o/photos%2Fuser%2Fold?alt=media&token=abc',
    'https://storage.googleapis.com/storage/v1/b/bucket/o/photos%2Fuser%2Fold?alt=media',
    'https://bucket.storage.googleapis.com/photos/user/old'
])('resolves managed photo URL %s', (url) => {
    expect(profilePhotoPath(url, 'bucket', 'photos', 'user')).toBe(
        'photos/user/old'
    );
});

it.each([
    null,
    '',
    'bad',
    'https://example.com/photos/user/old',
    'https://storage.googleapis.com/other/photos/user/old',
    'https://storage.googleapis.com/bucket/photos/other/old',
    'https://storage.googleapis.com/bucket/elsewhere/user/old',
    'https://storage.googleapis.com/bucket/photos/user/',
    'https://storage.googleapis.com/bucket/photos/user/%',
    'https://storage.googleapis.com/bucket/photos/user/old%2F..%2Fother',
    'https://storage.googleapis.com/bucket/photos/user/old%0A',
    'https://storage.googleapis.com/bucket/photos/user/a%5Cb',
    'https://storage.googleapis.com/bucket/photos/user//old',
    'http://storage.googleapis.com/bucket/photos/user/old',
    'https://storage.googleapis.com:8443/bucket/photos/user/old',
    'https://user@storage.googleapis.com/bucket/photos/user/old',
    'https://firebasestorage.googleapis.com/v0/b/other/o/photos%2Fuser%2Fold',
    'https://firebasestorage.googleapis.com/invalid'
])('does not resolve unmanaged or malformed URL %s', (url) => {
    expect(profilePhotoPath(url, 'bucket', 'photos', 'user')).toBeNull();
});

it('requires a configured bucket and respects encoded UIDs and custom prefixes', () => {
    expect(
        profilePhotoPath(
            'https://storage.googleapis.com/bucket/photos/user/old',
            undefined,
            'photos',
            'user'
        )
    ).toBeNull();
    expect(
        profilePhotoPath(
            'https://storage.googleapis.com/bucket/custom/photos/user%252Fid/old',
            'bucket',
            'custom/photos',
            'user/id'
        )
    ).toBe('custom/photos/user%2Fid/old');
});

import { hasPhotoSignature, isProfilePhotoPath } from './profiles-photo.js';

it.each([
    ['image/jpeg', [255, 216, 255]],
    ['image/png', [137, 80, 78, 71, 13, 10, 26, 10]],
    ['image/gif', Array.from('GIF89a', (char) => char.charCodeAt(0))],
    ['image/webp', Array.from('RIFF0000WEBP', (char) => char.charCodeAt(0))],
    ['image/avif', Array.from('0000ftypavif', (char) => char.charCodeAt(0))]
] as const)('checks %s image signatures', (type, bytes) => {
    expect(hasPhotoSignature(new Uint8Array(bytes), type)).toBe(true);
    expect(hasPhotoSignature(new Uint8Array([0]), type)).toBe(false);
});

it('rejects unknown photo signatures and invalid raw object paths', () => {
    expect(hasPhotoSignature(new Uint8Array(), 'unknown')).toBe(false);
    expect(isProfilePhotoPath(null, 'photos', 'user')).toBe(false);
    expect(isProfilePhotoPath('photos/user/new', 'photos', 'user')).toBe(true);
    expect(isProfilePhotoPath('photos/user/../new', 'photos', 'user')).toBe(
        false
    );
});
