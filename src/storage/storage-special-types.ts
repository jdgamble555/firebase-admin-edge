import type { StorageIamPolicy } from './storage-bucket-types.js';

export interface StorageNotificationConfig {
    topic: string;
    payload_format: 'JSON_API_V1' | 'NONE';
    event_types?: Array<
        | 'OBJECT_FINALIZE'
        | 'OBJECT_METADATA_UPDATE'
        | 'OBJECT_DELETE'
        | 'OBJECT_ARCHIVE'
    >;
    object_name_prefix?: string;
    custom_attributes?: Record<string, string>;
}
export interface StorageNotification extends StorageNotificationConfig {
    id: string;
}
export interface StorageManagedFolder {
    name: string;
    metageneration: string;
    id?: string;
    createTime?: string;
    updateTime?: string;
}
export interface StorageHmacKeyMetadata {
    accessId: string;
    projectId: string;
    serviceAccountEmail: string;
    state: 'ACTIVE' | 'INACTIVE' | 'DELETED';
    etag?: string;
    timeCreated?: string;
    updated?: string;
}
export interface StorageHmacKey {
    metadata: StorageHmacKeyMetadata;
    secret: string;
}
export interface StorageAclEntry {
    entity: string;
    role: 'OWNER' | 'READER' | 'WRITER';
    etag?: string;
    email?: string;
    entityId?: string;
}
export type StorageAclTarget =
    | { scope: 'bucket' }
    | { scope: 'defaultObject' }
    | { scope: 'object'; name: string; generation?: string };
export interface StorageResourceListOptions {
    pageToken?: string;
    maxResults?: number;
}
export interface StorageManagedFolderListOptions
    extends StorageResourceListOptions {
    prefix?: string;
}
export interface StorageHmacListOptions extends StorageResourceListOptions {
    serviceAccountEmail?: string;
    showDeletedKeys?: boolean;
}
export interface StoragePage<T> {
    items: T[];
    nextPageToken?: string;
}
export interface StorageManagedFolderOptions {
    ifMetagenerationMatch?: string;
    ifMetagenerationNotMatch?: string;
}
export interface StorageManagedFolderDeleteOptions
    extends StorageManagedFolderOptions {
    allowNonEmpty?: boolean;
}

/** @internal */
export type StorageSpecialOperation =
    | { kind: 'notificationCreate'; config: StorageNotificationConfig }
    | { kind: 'notificationList' }
    | { kind: 'notificationGet' | 'notificationDelete'; id: string }
    | { kind: 'folderCreate'; name: string }
    | { kind: 'folderGet'; name: string; options: StorageManagedFolderOptions }
    | {
          kind: 'folderDelete';
          name: string;
          options: StorageManagedFolderDeleteOptions;
      }
    | { kind: 'folderList'; options: StorageManagedFolderListOptions }
    | { kind: 'folderGetIam'; name: string }
    | { kind: 'folderSetIam'; name: string; policy: StorageIamPolicy }
    | { kind: 'folderTestIam'; name: string; permissions: string[] }
    | { kind: 'hmacCreate'; serviceAccountEmail: string }
    | { kind: 'hmacGet' | 'hmacDelete'; accessId: string }
    | {
          kind: 'hmacUpdate';
          accessId: string;
          state: 'ACTIVE' | 'INACTIVE';
          etag?: string;
      }
    | { kind: 'hmacList'; options: StorageHmacListOptions }
    | { kind: 'aclList'; target: StorageAclTarget }
    | { kind: 'aclGet' | 'aclDelete'; target: StorageAclTarget; entity: string }
    | {
          kind: 'aclCreate' | 'aclUpdate';
          target: StorageAclTarget;
          entry: StorageAclEntry;
      };

/** @internal */
export interface StorageSpecialResponses {
    notificationCreate: StorageNotification;
    notificationList: StoragePage<StorageNotification>;
    notificationGet: StorageNotification;
    notificationDelete: void;
    folderCreate: StorageManagedFolder;
    folderGet: StorageManagedFolder;
    folderDelete: void;
    folderList: StoragePage<StorageManagedFolder>;
    folderGetIam: StorageIamPolicy;
    folderSetIam: StorageIamPolicy;
    folderTestIam: string[];
    hmacCreate: StorageHmacKey;
    hmacGet: StorageHmacKeyMetadata;
    hmacUpdate: StorageHmacKeyMetadata;
    hmacList: StoragePage<StorageHmacKeyMetadata>;
    hmacDelete: void;
    aclList: StoragePage<StorageAclEntry>;
    aclGet: StorageAclEntry;
    aclCreate: StorageAclEntry;
    aclUpdate: StorageAclEntry;
    aclDelete: void;
}
