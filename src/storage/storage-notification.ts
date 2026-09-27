import type { Bucket } from './storage-bucket.js';
import type { Storage } from './storage.js';
import { storageData, storageResult } from './storage-results.js';
import type { StorageNotification } from './storage-special-types.js';

export class Notification {
    metadata?: StorageNotification;
    constructor(
        readonly bucket: Bucket,
        readonly id: string,
        private readonly storage: Storage
    ) {}

    getMetadata() {
        return storageResult(async () => {
            const result = await this.storage.getNotification(this.id);
            this.metadata = storageData(result);
            return this.metadata;
        });
    }

    get() {
        return storageResult(async () => {
            const result = await this.getMetadata();
            storageData(result);
            return this;
        });
    }

    async exists() {
        const { error } = await this.getMetadata();
        if (error?.code === 'storage/resource-not-found') {
            return { error: null, data: false } as const;
        }
        if (error) {
            return { error, data: null } as const;
        }
        return { error: null, data: true } as const;
    }

    delete() {
        return this.storage.deleteNotification(this.id);
    }
}
