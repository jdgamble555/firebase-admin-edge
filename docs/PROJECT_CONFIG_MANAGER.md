# ProjectConfigManager

[FirebaseAdminAuth](FIREBASE_ADMIN_AUTH.md)

Obtain a cached manager with `adminAuth.projectConfigManager()`. Its async methods
return `{ data, error }`. Configuration results are plain JSON objects.

```ts
const manager = adminAuth.projectConfigManager();
const current = await manager.getProjectConfig();
if (current.error) throw current.error;
console.log(current.data);

const updated = await manager.updateProjectConfig({
    emailPrivacyConfig: { enableImprovedEmailPrivacy: true },
    multiFactorConfig: {
        state: 'ENABLED',
        factorIds: ['phone'],
        providerConfigs: [
            { state: 'ENABLED', totpProviderConfig: { adjacentIntervals: 1 } }
        ]
    },
    smsRegionConfig: { allowlistOnly: { allowedRegions: ['US', 'CA'] } },
    passwordPolicyConfig: {
        enforcementState: 'ENFORCE',
        constraints: { minLength: 12, requireNumeric: true }
    },
    recaptchaConfig: { emailPasswordEnforcementState: 'AUDIT' },
    mobileLinksConfig: { domain: 'HOSTING_DOMAIN' }
});
if (updated.error) throw updated.error;
console.log(updated.data);
```

Updates must contain at least one supported setting. Omitted settings remain
unchanged; nested updates use field masks. Pass an empty `factorIds` array to
clear enabled phone factors. Project management always targets the parent project,
including when the manager is obtained from a tenant-scoped auth instance.

These operations require service-account permissions for the
[Identity Platform project configuration API](https://cloud.google.com/identity-platform/docs/reference/rest/v2/projects).
