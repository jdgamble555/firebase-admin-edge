# HmacKey

`const key = firebaseServer.storage.hmacKey(accessId)` constructs a reference. Key creation remains available as `storage.createHmacKey(serviceAccountEmail)`; store the secret securely when returned because it cannot be retrieved again.

Every async operation returns `{ error, data }`:

| Method        | Usage                                                              | Data                          |
| ------------- | ------------------------------------------------------------------ | ----------------------------- |
| `exists`      | `await key.exists()`                                               | Boolean                       |
| `get`         | `await key.get()`                                                  | This reference                |
| `getMetadata` | `await key.getMetadata()`                                          | Metadata                      |
| `setMetadata` | `await key.setMetadata({ state: 'INACTIVE', etag: previousEtag })` | Updated metadata              |
| `delete`      | `await key.delete()`                                               | `undefined`; deactivate first |

```ts
const { error, data } = await key.getMetadata();
if (error) {
    throw error;
}
console.log(key.id, data.state);
```
