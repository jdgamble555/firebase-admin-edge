import type { FirebaseAdminAuth } from './firebase-admin-auth.js';
import type {
    AuthConfigExecutor,
    CreateTenantRequest,
    UpdateTenantRequest,
    Tenant,
    ListTenantsResult
} from './auth-config-types.js';
import { validateTenantId } from './auth-config.js';

/** Manage tenants and obtain tenant-scoped authentication instances. */
export class TenantManager {
    private readonly instances = new Map<string, FirebaseAdminAuth>();

    /** @internal Obtain this manager from adminAuth.tenantManager(). */
    constructor(
        private readonly execute: AuthConfigExecutor,
        private readonly createAuth: (tenantId: string) => FirebaseAdminAuth
    ) {}

    authForTenant(tenantId: string): FirebaseAdminAuth {
        validateTenantId(tenantId);
        const existing = this.instances.get(tenantId);
        if (existing) return existing;
        const auth = this.createAuth(tenantId);
        this.instances.set(tenantId, auth);
        return auth;
    }

    createTenant(properties: CreateTenantRequest) {
        return this.execute<Tenant>({
            resource: 'tenant',
            action: 'create',
            properties
        });
    }

    getTenant(tenantId: string) {
        return this.execute<Tenant>({
            resource: 'tenant',
            action: 'get',
            id: tenantId
        });
    }

    updateTenant(tenantId: string, properties: UpdateTenantRequest) {
        return this.execute<Tenant>({
            resource: 'tenant',
            action: 'update',
            id: tenantId,
            properties
        });
    }

    deleteTenant(tenantId: string) {
        return this.execute<void>({
            resource: 'tenant',
            action: 'delete',
            id: tenantId
        });
    }

    listTenants(maxResults = 1000, pageToken?: string) {
        return this.execute<ListTenantsResult>({
            resource: 'tenant',
            action: 'list',
            maxResults,
            pageToken
        });
    }
}
