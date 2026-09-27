import type { Storage } from './storage.js';
import { storageResult, storageData } from './storage-results.js';
import type { StorageHmacKeyMetadata } from './storage-special-types.js';

export class HmacKey {
    metadata?: StorageHmacKeyMetadata;
    constructor(
        readonly id: string,
        readonly storage: Storage
    ) {}

    getMetadata() {
        return storageResult(async () => {
            const result = await this.storage.getHmacKey(this.id);
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

    setMetadata(metadata: { state: 'ACTIVE' | 'INACTIVE'; etag?: string }) {
        return storageResult(async () => {
            const result = await this.storage.updateHmacKey(
                this.id,
                metadata.state,
                metadata.etag
            );
            this.metadata = storageData(result);
            return this.metadata;
        });
    }

    delete() {
        return this.storage.deleteHmacKey(this.id);
    }
}
