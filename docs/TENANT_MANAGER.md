# TenantManager

[FirebaseAdminAuth](FIREBASE_ADMIN_AUTH.md) · [ProjectConfigManager](PROJECT_CONFIG_MANAGER.md)

Use `adminAuth.tenantManager()` to obtain a cached manager. Tenant CRUD methods
return `{ data, error }`; tenant records are plain JSON objects. Enable multi-tenancy
in your Identity Platform project before creating tenants. See Google's
[tenant management guide](https://cloud.google.com/identity-platform/docs/multi-tenancy-managing-tenants).

```ts
const manager = adminAuth.tenantManager();
const created = await manager.createTenant({
    displayName: 'Example organization',
    emailSignInConfig: { enabled: true, passwordRequired: false },
    anonymousSignInEnabled: false,
    multiFactorConfig: { state: 'ENABLED', factorIds: ['phone'] },
    testPhoneNumbers: { '+15555550100': '123456' }
});
if (created.error) throw created.error;
const tenantId = created.data.tenantId;

const current = await manager.getTenant(tenantId);
if (current.error) throw current.error;
console.log(current.data.emailSignInConfig);

const updated = await manager.updateTenant(tenantId, {
    displayName: 'Renamed organization',
    testPhoneNumbers: null // Clear configured test numbers.
});
if (updated.error) throw updated.error;

let pageToken: string | undefined;
do {
    const page = await manager.listTenants(100, pageToken);
    if (page.error) throw page.error;
    console.log(page.data.tenants);
    pageToken = page.data.pageToken;
} while (pageToken);

const tenantAuth = manager.authForTenant(tenantId);
console.log(tenantAuth.tenantId);
const user = await tenantAuth.getUser('user-id');
const providers = await tenantAuth.listProviderConfigs({ type: 'oidc' });
```

`authForTenant()` returns a cached `FirebaseAdminAuth` for that tenant, retaining
the service account, custom fetch, and token cache. Invalid tenant IDs throw
synchronously because this method does not perform a request. Its auth operations
use the same `{ data, error }` convention as the parent instance.

To delete a tenant when it is no longer needed:

```ts
const deleted = await manager.deleteTenant(tenantId);
if (deleted.error) throw deleted.error;
// Successful deletion returns undefined data.
```

`listTenants()` defaults to 1000 results, accepts 1–1000, and returns an optional
`pageToken`. Updates preserve omitted settings. Tenant settings also support SMS
region policies, reCAPTCHA, password policies, and email privacy as demonstrated
in the [project configuration guide](PROJECT_CONFIG_MANAGER.md).

`testPhoneNumbers` accepts at most ten phone-number/code pairs.
