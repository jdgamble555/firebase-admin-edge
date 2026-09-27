# Iam

`bucket.iam` provides policies and permission checks, each returning `{ error, data }`.

```ts
const iam = firebaseServer.storage.bucket().iam;
const { error, data } = await iam.getPolicy();
if (error) {
    throw error;
}
console.log(data.bindings);
```

| Method            | Usage                                                                          |
| ----------------- | ------------------------------------------------------------------------------ |
| `getPolicy`       | `await iam.getPolicy()`                                                        |
| `setPolicy`       | `await iam.setPolicy({ version: 3, etag: previousEtag, bindings })`            |
| `testPermissions` | `await iam.testPermissions(['storage.objects.get', 'storage.objects.delete'])` |

Permission data maps each requested permission to a boolean. Preserve existing bindings and the policy etag when updating policies.

Policy reads default to version 3 to preserve conditions. Select a supported version and requester-pays project explicitly with `await iam.getPolicy({ requestedPolicyVersion: 3, userProject: 'billing-project' })`. `setPolicy(policy, { userProject })` and `testPermissions(permissions, { userProject })` accept the same billing option.
