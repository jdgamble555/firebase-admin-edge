export interface StorageCorsRule {
    origin: string[];
    method: string[];
    responseHeader?: string[];
    maxAgeSeconds?: number;
}

export interface StorageLifecycleRule {
    action: {
        type: 'Delete' | 'SetStorageClass' | 'AbortIncompleteMultipartUpload';
        storageClass?: string;
    };
    condition: {
        age?: number;
        createdBefore?: string;
        isLive?: boolean;
        numNewerVersions?: number;
        matchesStorageClass?: string[];
        matchesPrefix?: string[];
        matchesSuffix?: string[];
        daysSinceCustomTime?: number;
        customTimeBefore?: string;
        daysSinceNoncurrentTime?: number;
        noncurrentTimeBefore?: string;
    };
}

export interface StorageBucketUpdate {
    rpo?: 'DEFAULT' | 'ASYNC_TURBO';
    acl?: import('./storage-special-types.js').StorageAclEntry[] | null;
    defaultObjectAcl?: import('./storage-special-types.js').StorageAclEntry[];
    logging?: { logBucket?: string; logObjectPrefix?: string } | null;
    website?: { mainPageSuffix?: string; notFoundPage?: string } | null;
    cors?: StorageCorsRule[] | null;
    lifecycle?: { rule: StorageLifecycleRule[] } | null;
    versioning?: { enabled: boolean };
    labels?: Record<string, string | null>;
    storageClass?: string;
    defaultEventBasedHold?: boolean;
    billing?: { requesterPays: boolean };
    encryption?: { defaultKmsKeyName: string } | null;
    retentionPolicy?: { retentionPeriod: string | number } | null;
    softDeletePolicy?: { retentionDurationSeconds: string | number };
    iamConfiguration?: {
        uniformBucketLevelAccess?: { enabled: boolean };
        publicAccessPrevention?: 'enforced' | 'inherited';
    };
    autoclass?: { enabled: boolean; terminalStorageClass?: string };
}

export interface StorageBucketCreateOptions extends StorageBucketUpdate {
    location: string;
    customPlacementConfig?: { dataLocations: string[] };
    hierarchicalNamespace?: { enabled: boolean };
    dataLocations?: string[];
    enableObjectRetention?: boolean;
    predefinedAcl?: string;
    predefinedDefaultObjectAcl?: string;
    projection?: 'full' | 'noAcl';
    userProject?: string;
    requesterPays?: boolean;
    standard?: boolean;
    archive?: boolean;
    coldline?: boolean;
    nearline?: boolean;
    regional?: boolean;
    multiRegional?: boolean;
    dra?: boolean;
}

export interface StorageBucketMetadata {
    name: string;
    metageneration: string;
    location?: string;
    storageClass?: string;
    cors?: StorageCorsRule[];
    lifecycle?: { rule: StorageLifecycleRule[] };
    versioning?: { enabled: boolean };
    labels?: Record<string, string>;
    [field: string]: unknown;
}

export interface StorageBucketOptions {
    generation?: string;
    softDeleted?: boolean;
    userProject?: string;
    ifMetagenerationMatch?: string;
    ifMetagenerationNotMatch?: string;
}

export interface StorageBucketListOptions {
    prefix?: string;
    pageToken?: string;
    maxResults?: number;
}

export interface StorageBucketListResult {
    buckets: StorageBucketMetadata[];
    nextPageToken?: string;
}

export interface StorageIamPolicy {
    version?: 1 | 3;
    etag?: string;
    bindings: Array<{
        role: string;
        members: string[];
        condition?: { title: string; expression: string; description?: string };
    }>;
}

/** @internal */
export type StorageBucketOperation =
    | { kind: 'lockRetention'; options: { ifMetagenerationMatch: string } }
    | { kind: 'get'; options: StorageBucketOptions }
    | {
          kind: 'update';
          metadata: StorageBucketUpdate;
          options: StorageBucketOptions;
      }
    | { kind: 'create'; metadata: StorageBucketCreateOptions }
    | { kind: 'delete'; options: StorageBucketOptions }
    | { kind: 'list'; options: StorageBucketListOptions }
    | { kind: 'getIam'; requestedPolicyVersion?: 1 | 3; userProject?: string }
    | { kind: 'setIam'; policy: StorageIamPolicy }
    | { kind: 'testIam'; permissions: string[] };

/** @internal */
export interface StorageBucketResponses {
    lockRetention: StorageBucketMetadata;
    get: StorageBucketMetadata;
    update: StorageBucketMetadata;
    create: StorageBucketMetadata;
    delete: void;
    list: StorageBucketListResult;
    getIam: StorageIamPolicy;
    setIam: StorageIamPolicy;
    testIam: string[];
}
