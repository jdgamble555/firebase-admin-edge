import type { FirebaseEdgeError } from '../auth/errors.js';
import type { CRC32CValidatorGenerator } from './storage-checksum.js';

export type StorageResult<T> =
    | { error: null; data: T }
    | { error: FirebaseEdgeError; data: null };

/** Cloud Storage object metadata. Large integer fields stay as strings. */
export interface StorageFileMetadata {
    name: string;
    bucket: string;
    generation: string;
    metageneration?: string;
    size: string;
    contentType?: string;
    cacheControl?: string;
    contentDisposition?: string;
    contentEncoding?: string;
    contentLanguage?: string;
    timeCreated?: string;
    updated?: string;
    md5Hash?: string;
    crc32c?: string;
    metadata?: Record<string, string>;
    restoreToken?: string;
    softDeleteTime?: string;
    hardDeleteTime?: string;
    storageClass?: string;
    componentCount?: number;
    retentionExpirationTime?: string;
}

export type StorageUploadData =
    | string
    | Blob
    | Uint8Array<ArrayBuffer>
    | ArrayBuffer;

export interface StoragePreconditions {
    userProject?: string;
    ifGenerationMatch?: string;
    ifGenerationNotMatch?: string;
    ifMetagenerationMatch?: string;
    ifMetagenerationNotMatch?: string;
}

export interface StorageReadOptions extends StoragePreconditions {
    softDeleted?: boolean;
    restoreToken?: string;
    generation?: string;
}

export interface StorageDownloadOptions extends StorageReadOptions {
    crc32cGenerator?: CRC32CValidatorGenerator;
    checksumAlgorithm?: 'crc32c' | 'md5';
    /** Inclusive byte offsets. */
    start?: number;
    end?: number;
    verifyChecksum?: boolean;
}

export interface StorageTransferProgress {
    bytesTransferred: number;
    totalBytes?: number;
    complete: boolean;
}

export type StorageProgressCallback = (
    progress: StorageTransferProgress
) => void | Promise<void>;

export interface StorageUploadOptions extends StoragePreconditions {
    crc32cGenerator?: CRC32CValidatorGenerator;
    predefinedAcl?: string;
    kmsKeyName?: string;
    md5Hash?: 'auto' | string;
    metadata?: StorageMetadataUpdate;
    contentType?: string;
    /** Use "0" to create only if the object does not already exist. */
    ifGenerationMatch?: string;
    crc32c?: 'auto' | string;
    onProgress?: StorageProgressCallback;
}

export interface StorageDeleteOptions extends StorageReadOptions {
    ifGenerationMatch?: string;
}

export interface StorageMetadataUpdate {
    retention?: { mode: 'Locked' | 'Unlocked'; retainUntilTime: string } | null;
    acl?: import('./storage-special-types.js').StorageAclEntry[] | null;
    storageClass?: string;
    temporaryHold?: boolean;
    eventBasedHold?: boolean;
    customTime?: string;
    contentType?: string | null;
    cacheControl?: string | null;
    contentDisposition?: string | null;
    contentEncoding?: string | null;
    contentLanguage?: string | null;
    /** Null removes all custom metadata; null values remove individual keys. */
    metadata?: Record<string, string | number | boolean | null> | null;
}

export interface StorageMetadataOptions extends StorageDeleteOptions {
    overrideUnlockedRetention?: boolean;
    ifMetagenerationMatch?: string;
}

export interface StorageCopyOptions extends StoragePreconditions {
    predefinedAcl?: string;
    token?: string;
    metadata?: StorageMetadataUpdate;
    destinationKmsKeyName?: string;
    destinationEncryptionKey?: string | Uint8Array<ArrayBuffer>;
    destinationBucket?: string;
    sourceGeneration?: string;
    ifSourceGenerationMatch?: string;
    ifSourceMetagenerationMatch?: string;
}

export interface StorageResumableOptions
    extends Omit<
        StorageUploadOptions,
        'crc32c' | 'md5Hash' | 'onProgress' | 'crc32cGenerator'
    > {
    md5Hash?: string;
    origin?: string;
    metadata?: StorageMetadataUpdate;
    size?: number;
    crc32c?: string;
}

export interface StorageChunkOptions {
    md5Hash?: string;
    offset: number;
    /** Omit for a non-final chunk when the total size is not known yet. */
    totalSize?: number;
    /** Whole-object checksum, supplied only on the final chunk. */
    crc32c?: string;
    onProgress?: StorageProgressCallback;
}

export type StorageUploadProgress =
    | { complete: false; nextOffset: number }
    | { complete: true; metadata: StorageFileMetadata };

export interface StorageComposeSource {
    name: string;
    generation?: string;
    objectPreconditions?: { ifGenerationMatch: string };
}

export interface StorageComposeOptions extends StoragePreconditions {
    kmsKeyName?: string;
    destinationPredefinedAcl?: string;
    metadata?: StorageMetadataUpdate;
}

export interface StorageRestoreOptions extends StoragePreconditions {
    projection?: 'full' | 'noAcl';
    generation: string;
    restoreToken?: string;
    copySourceAcl?: boolean;
}

export interface StorageDeleteTarget extends StorageDeleteOptions {
    name: string;
}

export interface StorageBatchDeleteOptions {
    concurrency?: number;
    ignoreNotFound?: boolean;
}

export interface StorageBatchDeleteResult {
    results: Array<{
        name: string;
        generation?: string;
        error: FirebaseEdgeError | null;
    }>;
}

export interface StorageSignedUrlOptions {
    action: 'read' | 'write';
    /** Integer lifetime from 1 to 604800 seconds. Defaults to 900. */
    expiresInSeconds?: number;
    /** For write URLs, the caller must send this exact Content-Type. */
    contentType?: string;
}

export interface StorageListOptions {
    userProject?: string;
    fields?: string;
    includeFoldersAsPrefixes?: boolean;
    includeTrailingDelimiter?: boolean;
    projection?: 'full' | 'noAcl';
    prefix?: string;
    delimiter?: string;
    maxResults?: number;
    pageToken?: string;
    versions?: boolean;
    softDeleted?: boolean;
    startOffset?: string;
    endOffset?: string;
    matchGlob?: string;
}

export interface StorageListResult {
    files: StorageFileMetadata[];
    prefixes: string[];
    nextPageToken?: string;
}

/** @internal */
export type StorageOperation =
    | {
          kind: 'upload';
          name: string;
          body: StorageUploadData;
          options: StorageUploadOptions;
      }
    | {
          kind: 'download' | 'stream';
          name: string;
          options?: StorageDownloadOptions;
      }
    | { kind: 'metadata'; name: string; options?: StorageReadOptions }
    | { kind: 'resumable'; name: string; options: StorageResumableOptions }
    | {
          kind: 'compose';
          name: string;
          sources: StorageComposeSource[];
          options: StorageComposeOptions;
      }
    | { kind: 'restore'; name: string; options: StorageRestoreOptions }
    | { kind: 'delete'; name: string; options: StorageDeleteOptions }
    | {
          kind: 'updateMetadata';
          name: string;
          metadata: StorageMetadataUpdate;
          options: StorageMetadataOptions;
      }
    | {
          kind: 'copy';
          name: string;
          destination: string;
          options: StorageCopyOptions;
      }
    | { kind: 'list'; options: StorageListOptions };

/** @internal */
export interface StorageResponses {
    upload: StorageFileMetadata;
    download: Uint8Array<ArrayBuffer>;
    metadata: StorageFileMetadata;
    delete: void;
    list: StorageListResult;
    updateMetadata: StorageFileMetadata;
    copy: StorageFileMetadata;
    stream: Response;
    resumable: string;
    compose: StorageFileMetadata;
    restore: StorageFileMetadata;
}
