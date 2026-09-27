import type { Storage } from './storage.js';
import { storageData, storageResult } from './storage-results.js';
import type {
    StorageAclTarget,
    StorageAclEntry
} from './storage-special-types.js';

/** Admin-style ACL operations; async methods retain StorageResult. */
export class Acl {
    readonly readers: AclRole;
    readonly writers: AclRole;
    readonly owners: AclRole;

    constructor(
        private readonly resolveStorage: Storage | (() => Storage),
        private readonly target: StorageAclTarget
    ) {
        this.readers = new AclRole(this, 'READER');
        this.writers = new AclRole(this, 'WRITER');
        this.owners = new AclRole(this, 'OWNER');
    }

    private get storage() {
        return typeof this.resolveStorage === 'function'
            ? this.resolveStorage()
            : this.resolveStorage;
    }

    add(options: { entity: string; role: StorageAclEntry['role'] }) {
        return storageResult(async () => {
            const result = await this.storage.createAcl(this.target, options);
            return storageData(result);
        });
    }

    update(options: { entity: string; role: StorageAclEntry['role'] }) {
        return storageResult(async () => {
            const result = await this.storage.updateAcl(this.target, options);
            return storageData(result);
        });
    }

    get(options: { entity: string }): ReturnType<Storage['getAcl']>;
    get(options?: { entity?: undefined }): ReturnType<Storage['listAcl']>;
    get(options: { entity?: string } = {}) {
        return storageResult(async () => {
            if (options.entity !== undefined) {
                const result = await this.storage.getAcl(
                    this.target,
                    options.entity
                );
                return storageData(result);
            }
            const result = await this.storage.listAcl(this.target);
            return storageData(result);
        });
    }

    delete(options: { entity: string }) {
        return storageResult(async () => {
            const result = await this.storage.deleteAcl(
                this.target,
                options.entity
            );
            return storageData(result);
        });
    }
}

/** Convenience entity methods shared by readers, writers and owners. */
export class AclRole {
    constructor(
        private readonly acl: Acl,
        private readonly role: StorageAclEntry['role']
    ) {}
    addAllUsers() {
        return this.acl.add({ entity: 'allUsers', role: this.role });
    }
    deleteAllUsers() {
        return this.acl.delete({ entity: 'allUsers' });
    }
    addAllAuthenticatedUsers() {
        return this.acl.add({
            entity: 'allAuthenticatedUsers',
            role: this.role
        });
    }
    deleteAllAuthenticatedUsers() {
        return this.acl.delete({ entity: 'allAuthenticatedUsers' });
    }
    addUser(email: string) {
        return this.acl.add({ entity: `user-${email}`, role: this.role });
    }
    deleteUser(email: string) {
        return this.acl.delete({ entity: `user-${email}` });
    }
    addGroup(email: string) {
        return this.acl.add({ entity: `group-${email}`, role: this.role });
    }
    deleteGroup(email: string) {
        return this.acl.delete({ entity: `group-${email}` });
    }
    addDomain(domain: string) {
        return this.acl.add({ entity: `domain-${domain}`, role: this.role });
    }
    deleteDomain(domain: string) {
        return this.acl.delete({ entity: `domain-${domain}` });
    }
    addProject(role: 'owners' | 'editors' | 'viewers', projectId: string) {
        return this.acl.add({
            entity: `project-${role}-${projectId}`,
            role: this.role
        });
    }
    deleteProject(role: 'owners' | 'editors' | 'viewers', projectId: string) {
        return this.acl.delete({ entity: `project-${role}-${projectId}` });
    }
}
