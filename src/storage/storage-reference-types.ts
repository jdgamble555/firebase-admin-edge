import type {
    StorageListOptions,
    StorageMetadataUpdate,
    StorageDownloadOptions,
    StorageCopyOptions
} from './storage-types.js';
import type { StorageReadOptions } from './storage-types.js';
import type { StorageUploadStreamOptions } from './storage-upload-stream.js';
import type { CRC32CValidatorGenerator } from './storage-checksum.js';

export interface PreconditionOptions {
    userProject?: string;
    ifGenerationMatch?: string | number;
    ifGenerationNotMatch?: string | number;
    ifMetagenerationMatch?: string | number;
    ifMetagenerationNotMatch?: string | number;
}
export interface FileOptions {
    crc32cGenerator?: CRC32CValidatorGenerator;
    generation?: string | number;
    preconditionOpts?: PreconditionOptions;
    userProject?: string;
    encryptionKey?: string | Uint8Array<ArrayBuffer>;
    kmsKeyName?: string;
    restoreToken?: string;
}
export interface BucketOptions
    extends Omit<FileOptions, 'encryptionKey' | 'restoreToken'> {
    softDeleted?: boolean;
}
export interface SaveOptions
    extends Omit<StorageUploadStreamOptions, 'metadata'> {
    metadata?: StorageMetadataUpdate;
    preconditionOpts?: PreconditionOptions;
    resumable?: boolean;
    validation?: 'crc32c' | 'md5' | boolean;
    gzip?: boolean | 'auto';
    timeout?: number;
    highWaterMark?: number;
    uri?: string;
    public?: boolean;
    private?: boolean;
    onUploadProgress?: (progress: {
        bytesWritten: number;
        contentLength?: number;
    }) => void | Promise<void>;
}
export interface FileReadOptions
    extends Omit<StorageReadOptions, keyof PreconditionOptions | 'generation'>,
        PreconditionOptions {
    generation?: string | number;
    autoCreate?: boolean;
    overrideUnlockedRetention?: boolean;
}
export interface DownloadOptions
    extends Omit<
            StorageDownloadOptions,
            keyof PreconditionOptions | 'generation'
        >,
        FileReadOptions {
    validation?: 'crc32c' | 'md5' | boolean;
    destination?: string;
    decompress?: boolean;
    encryptionKey?: string | Uint8Array<ArrayBuffer>;
}
export interface GetFilesOptions extends StorageListOptions {
    autoPaginate?: boolean;
    maxApiCalls?: number;
}
export interface CopyOptions
    extends Omit<StorageCopyOptions, 'metadata'>,
        StorageMetadataUpdate {
    preconditionOpts?: PreconditionOptions;
    destinationKmsKeyName?: string;
}
export interface GetSignedUrlOptions {
    host?: string;
    signingEndpoint?: string;
    action: 'read' | 'write' | 'delete' | 'resumable' | 'list';
    expires: number | string | Date;
    accessibleAt?: number | string | Date;
    version?: 'v2' | 'v4';
    contentType?: string;
    contentMd5?: string;
    extensionHeaders?: Record<string, string | string[] | number | undefined>;
    queryParams?: Record<string, string | number | boolean>;
    responseDisposition?: string;
    promptSaveAs?: string;
    responseType?: string;
    virtualHostedStyle?: boolean;
    cname?: string;
}
