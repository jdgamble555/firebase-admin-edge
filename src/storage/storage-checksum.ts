import { FirebaseEdgeError } from '../auth/errors.js';
import { StorageMd5 } from './storage-md5.js';
import type {
    StorageUploadData,
    StorageFileMetadata
} from './storage-types.js';

const table = Uint32Array.from({ length: 256 }, (_, index) => {
    let crc = index;
    for (let bit = 0; bit < 8; bit++) {
        crc = (crc >>> 1) ^ (crc & 1 ? 0x82f63b78 : 0);
    }
    return crc >>> 0;
});

export interface CRC32CValidator {
    update(bytes: Uint8Array): void;
    toString(): string;
    validate(value: string): boolean;
}

export type CRC32CValidatorGenerator = () => CRC32CValidator;

/** @internal Adapt SDK validators and combine a resumed prefix with the suffix CRC. */
export function createStorageCrc32c(
    generator?: CRC32CValidatorGenerator,
    initial?: string | number
): Pick<StorageCrc32c, 'update' | 'digest'> {
    const prefix = new StorageCrc32c(initial);
    if (generator === undefined) {
        return prefix;
    }
    if (typeof generator !== 'function') {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'crc32cGenerator must be a function.'
        });
    }
    const validator = generator();
    if (
        !validator ||
        typeof validator.update !== 'function' ||
        typeof validator.toString !== 'function' ||
        typeof validator.validate !== 'function'
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'crc32cGenerator must return a CRC32C validator.'
        });
    }
    let length = 0;
    return {
        update(bytes) {
            validator.update(bytes);
            length += bytes.length;
        },
        digest() {
            const digest = validator.toString();
            validateStorageCrc32c(digest);
            if (!validator.validate(digest)) {
                throw new FirebaseEdgeError({
                    code: 'storage/checksum-mismatch',
                    message: 'The custom CRC32C validator rejected its digest.'
                });
            }
            if (initial === undefined) {
                return digest;
            }
            return combineStorageCrc32c(prefix.digest(), digest, length);
        }
    };
}

/** Apply the Castagnoli zero-byte operator to concatenate two finalized CRCs. */
function combineStorageCrc32c(
    prefix: string,
    suffix: string,
    length: number
): string {
    const decode = (value: string) => {
        const bytes = Uint8Array.from(atob(value), (character) =>
            character.charCodeAt(0)
        );
        return new DataView(bytes.buffer).getUint32(0);
    };
    const multiply = (matrix: Uint32Array, vector: number) => {
        let result = 0;
        let index = 0;
        while (vector !== 0) {
            if (vector & 1) {
                result ^= matrix[index]!;
            }
            vector >>>= 1;
            index++;
        }
        return result >>> 0;
    };
    let matrix = Uint32Array.from({ length: 32 }, (_, index) => {
        const value = (2 ** index) >>> 0;
        return ((value >>> 8) ^ table[value & 255]!) >>> 0;
    });
    let crc = decode(prefix);
    while (length > 0) {
        if (length % 2 === 1) {
            crc = multiply(matrix, crc);
        }
        length = Math.floor(length / 2);
        matrix = matrix.map((value) => multiply(matrix, value));
    }
    const result = (crc ^ decode(suffix)) >>> 0;
    return btoa(
        String.fromCharCode(
            result >>> 24,
            (result >>> 16) & 255,
            (result >>> 8) & 255,
            result & 255
        )
    );
}

/** @internal Incremental CRC32C shared by streamed downloads and uploads. */
export class StorageCrc32c {
    private crc = 0xffffffff;

    constructor(initial?: string | number) {
        if (initial === undefined) {
            return;
        }
        if (typeof initial === 'string') {
            validateStorageCrc32c(initial);
            const bytes = Uint8Array.from(atob(initial), (value) =>
                value.charCodeAt(0)
            );
            this.crc = new DataView(bytes.buffer).getUint32(0) ^ 0xffffffff;
            return;
        }
        if (
            !Number.isInteger(initial) ||
            initial < -0x80000000 ||
            initial > 0xffffffff
        ) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message:
                    'resumeCRC32C must be a 32-bit CRC32C or its base64 digest.'
            });
        }
        this.crc = initial ^ 0xffffffff;
    }

    update(bytes: Uint8Array): void {
        for (const byte of bytes) {
            this.crc = (this.crc >>> 8) ^ table[(this.crc ^ byte) & 255]!;
        }
    }

    digest(): string {
        const result = (this.crc ^ 0xffffffff) >>> 0;
        return btoa(
            String.fromCharCode(
                result >>> 24,
                (result >>> 16) & 255,
                (result >>> 8) & 255,
                result & 255
            )
        );
    }

    toString(): string {
        return this.digest();
    }

    validate(value: string): boolean {
        return this.digest() === value;
    }
}

/** Compute a Cloud Storage CRC32C (base64, big-endian) using web-native input types. */
export async function calculateStorageCrc32c(
    input: StorageUploadData,
    generator?: CRC32CValidatorGenerator
): Promise<string> {
    return calculateStorageChecksum(input, 'crc32c', generator);
}

/** Compute the base64 MD5 used for Cloud Storage object integrity validation. */
export async function calculateStorageMd5(
    input: StorageUploadData
): Promise<string> {
    return calculateStorageChecksum(input, 'md5');
}

async function calculateStorageChecksum(
    input: StorageUploadData,
    algorithm: 'crc32c' | 'md5',
    generator?: CRC32CValidatorGenerator
): Promise<string> {
    const blob = storageUploadBlob(input);
    const checksum =
        algorithm === 'md5' ? new StorageMd5() : createStorageCrc32c(generator);
    const reader = blob.stream().getReader();
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) {
                break;
            }
            checksum.update(value);
        }
    } finally {
        reader.releaseLock();
    }
    return checksum.digest();
}

/** @internal Centralize byte sizing and UTF-8 conversion for progress and checksums. */
export function storageUploadBlob(input: StorageUploadData): Blob {
    if (
        typeof input !== 'string' &&
        !(input instanceof Blob) &&
        !(input instanceof ArrayBuffer) &&
        !(input instanceof Uint8Array)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'Invalid upload data.'
        });
    }
    return input instanceof Blob ? input : new Blob([input]);
}

/** @internal Detect checksum mismatches even when the service accepted the upload. */
export function verifyStorageUpload(
    checksum: string | undefined,
    metadata: StorageFileMetadata,
    md5Hash?: string
) {
    if (md5Hash !== undefined && metadata.md5Hash !== md5Hash) {
        throw new FirebaseEdgeError(
            {
                code: metadata.md5Hash
                    ? 'storage/checksum-mismatch'
                    : 'storage/checksum-unavailable',
                message:
                    'The accepted upload could not be verified against the expected MD5.'
            },
            {
                context: {
                    name: metadata.name,
                    bucket: metadata.bucket,
                    generation: metadata.generation,
                    expectedMd5: md5Hash,
                    actualMd5: metadata.md5Hash
                }
            }
        );
    }
    if (checksum === undefined || metadata.crc32c === checksum) {
        return;
    }
    throw new FirebaseEdgeError(
        {
            code: metadata.crc32c
                ? 'storage/checksum-mismatch'
                : 'storage/checksum-unavailable',
            message:
                'The accepted upload could not be verified against the expected CRC32C.'
        },
        {
            context: {
                name: metadata.name,
                bucket: metadata.bucket,
                generation: metadata.generation,
                expectedCrc32c: checksum,
                actualCrc32c: metadata.crc32c
            }
        }
    );
}

/** @internal Require a canonical base64-encoded four-byte CRC32C. */
export function validateStorageCrc32c(value: unknown): asserts value is string {
    if (
        typeof value !== 'string' ||
        !/^[A-Za-z0-9+/]{5}[AQgw]==$/.test(value)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'crc32c must be a base64-encoded four-byte checksum.'
        });
    }
}

/** @internal Require canonical base64 representing a 16-byte MD5 digest. */
export function validateStorageMd5(value: unknown): asserts value is string {
    if (
        typeof value !== 'string' ||
        !/^[A-Za-z0-9+/]{21}[AQgw]==$/.test(value)
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/invalid-argument',
            message: 'md5Hash must be a base64-encoded 16-byte checksum.'
        });
    }
}

/** @internal Validate downloaded bytes against the whole-object response checksum. */
export async function verifyStorageDownload(
    bytes: Uint8Array<ArrayBuffer>,
    response: Response,
    algorithm: 'crc32c' | 'md5' = 'crc32c',
    generator?: CRC32CValidatorGenerator
) {
    const hash = storageResponseChecksum(response, algorithm);
    const actual = await calculateStorageChecksum(bytes, algorithm, generator);
    if (actual !== hash) {
        throw new FirebaseEdgeError({
            code: 'storage/checksum-mismatch',
            message: `Downloaded bytes do not match the Storage ${algorithm} checksum.`
        });
    }
}

/** @internal Reject responses for which a whole-object checksum cannot be verified. */
function storageResponseChecksum(
    response: Response,
    algorithm: 'crc32c' | 'md5' = 'crc32c'
): string {
    const hash = response.headers
        .get('x-goog-hash')
        ?.split(',')
        .map((value) => value.trim())
        .find((value) => value.startsWith(`${algorithm}=`))
        ?.slice(algorithm.length + 1);
    if (
        response.status === 206 ||
        response.headers.has('content-encoding') ||
        !hash
    ) {
        throw new FirebaseEdgeError({
            code: 'storage/checksum-unavailable',
            message: `Checksum verification requires a full, unencoded response with a ${algorithm} header.`
        });
    }
    return hash;
}

/** @internal Preserve backpressure and report integrity errors when the stream reaches EOF. */
export function verifyStorageStream(
    response: Response,
    algorithm: 'crc32c' | 'md5' = 'crc32c',
    generator?: CRC32CValidatorGenerator
): Response {
    let expected: string;
    let checksum: Pick<StorageCrc32c, 'update' | 'digest'>;
    try {
        expected = storageResponseChecksum(response, algorithm);
        checksum =
            algorithm === 'md5'
                ? new StorageMd5()
                : createStorageCrc32c(generator);
    } catch (cause) {
        void response.body?.cancel().catch(() => {});
        throw cause;
    }
    if (!response.body) {
        throw new FirebaseEdgeError({
            code: 'storage/checksum-unavailable',
            message: 'The response has no readable body.'
        });
    }
    const reader = response.body.getReader();
    const body = new ReadableStream<Uint8Array>(
        {
            async pull(controller) {
                try {
                    const { done, value } = await reader.read();
                    if (!done) {
                        checksum.update(value);
                        controller.enqueue(value);
                        return;
                    }
                    reader.releaseLock();
                    if (checksum.digest() !== expected) {
                        controller.error(
                            new FirebaseEdgeError({
                                code: 'storage/checksum-mismatch',
                                message: `Downloaded bytes do not match the Storage ${algorithm} checksum.`
                            })
                        );
                        return;
                    }
                    controller.close();
                } catch (cause) {
                    await reader.cancel(cause).catch(() => {});
                    reader.releaseLock();
                    controller.error(cause);
                }
            },
            async cancel(reason) {
                try {
                    await reader.cancel(reason);
                } finally {
                    reader.releaseLock();
                }
            }
        },
        { highWaterMark: 0 }
    );
    return new Response(body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
    });
}
