import type { Storage } from './storage.js';
import type { StorageIamPolicy } from './storage-bucket-types.js';
import { storageResult, storageData } from './storage-results.js';

export class Iam {
    constructor(private readonly resolveStorage: Storage | (() => Storage)) {}

    private get storage() {
        return typeof this.resolveStorage === 'function'
            ? this.resolveStorage()
            : this.resolveStorage;
    }

    getPolicy(options?: {
        requestedPolicyVersion?: 1 | 3;
        userProject?: string;
    }) {
        return storageResult(async () => {
            const result = options
                ? await this.storage.getIamPolicy(options)
                : await this.storage.getIamPolicy();
            return storageData(result);
        });
    }

    setPolicy(
        policy: StorageIamPolicy,
        options: { userProject?: string } = {}
    ) {
        return storageResult(async () => {
            const storage = options.userProject
                ? this.storage.scoped(options)
                : this.storage;
            const result = await storage.setIamPolicy(policy);
            return storageData(result);
        });
    }

    testPermissions(
        permissions: string[],
        options: { userProject?: string } = {}
    ) {
        return storageResult(async () => {
            const storage = options.userProject
                ? this.storage.scoped(options)
                : this.storage;
            const result = await storage.testIamPermissions(permissions);
            const granted = new Set(storageData(result));
            return Object.fromEntries(
                permissions.map((permission) => [
                    permission,
                    granted.has(permission)
                ])
            );
        });
    }
}
