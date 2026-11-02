export const PROFILE_PHOTO_CONTENT_TYPES = [
    'image/jpeg',
    'image/png',
    'image/webp',
    'image/gif',
    'image/avif'
];

/** @internal Check image signatures without decoding untrusted image data. */
export function hasPhotoSignature(
    bytes: Uint8Array,
    contentType: string
): boolean {
    const header = String.fromCharCode(...bytes.slice(0, 16));
    if (contentType === 'image/jpeg') {
        return bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
    }
    if (contentType === 'image/png') {
        return [137, 80, 78, 71, 13, 10, 26, 10].every(
            (byte, index) => bytes[index] === byte
        );
    }
    if (contentType === 'image/gif') {
        return header.startsWith('GIF87a') || header.startsWith('GIF89a');
    }
    if (contentType === 'image/webp') {
        return header.startsWith('RIFF') && header.slice(8, 12) === 'WEBP';
    }
    if (contentType === 'image/avif') {
        return (
            header.slice(4, 8) === 'ftyp' &&
            ['avif', 'avis'].includes(header.slice(8, 12))
        );
    }
    return false;
}

/** @internal Keep object operations within the configured user's photo directory. */
export function isProfilePhotoPath(
    path: unknown,
    prefix: string,
    uid: string
): path is string {
    if (typeof path !== 'string') {
        return false;
    }
    const userPrefix = `${prefix}/${encodeURIComponent(uid)}/`;
    return (
        path.startsWith(userPrefix) &&
        path.length > userPrefix.length &&
        !path
            .split('/')
            .some(
                (segment) => !segment || segment === '.' || segment === '..'
            ) &&
        !/[\\\u0000-\u001f\u007f]/.test(path)
    );
}

/** @internal Resolve only photos belonging to this user's configured Storage prefix. */
export function profilePhotoPath(
    photoURL: unknown,
    bucket: string | undefined,
    prefix: string,
    uid: string
): string | null {
    if (typeof photoURL !== 'string' || !bucket) {
        return null;
    }
    try {
        const url = new URL(photoURL);
        if (
            url.protocol !== 'https:' ||
            url.username ||
            url.password ||
            url.port
        ) {
            return null;
        }
        let objectPath: string;
        if (url.hostname === 'firebasestorage.googleapis.com') {
            const match = /^\/v0\/b\/([^/]+)\/o\/(.+)$/.exec(url.pathname);
            if (!match || decodeURIComponent(match[1]!) !== bucket) {
                return null;
            }
            objectPath = decodeURIComponent(match[2]!);
        } else if (url.hostname === 'storage.googleapis.com') {
            const match =
                /^\/(?:storage\/v1\/b\/([^/]+)\/o|([^/]+))\/(.+)$/.exec(
                    url.pathname
                );
            if (
                !match ||
                decodeURIComponent(match[1] ?? match[2]!) !== bucket
            ) {
                return null;
            }
            objectPath = decodeURIComponent(match[3]!);
        } else if (url.hostname === `${bucket}.storage.googleapis.com`) {
            objectPath = decodeURIComponent(url.pathname.slice(1));
        } else {
            return null;
        }
        if (!isProfilePhotoPath(objectPath, prefix, uid)) {
            return null;
        }
        return objectPath;
    } catch {
        return null;
    }
}
