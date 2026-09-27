# Acl

Use `bucket.acl`, `bucket.acl.default`, or `file.acl` for legacy ACLs. Uniform bucket-level access disables these APIs; use [IAM](IAM.md) for those buckets. Every async call returns `{ error, data }`.

```ts
const acl = firebaseServer.storage.bucket().acl;
const { error, data } = await acl.get();
if (error) {
    throw error;
}
console.log(data.items);
```

| Method   | Usage                                                                    |
| -------- | ------------------------------------------------------------------------ |
| `add`    | `await acl.add({ entity: 'user-person@example.com', role: 'READER' })`   |
| `update` | `await acl.update({ entity: 'user-person@example.com', role: 'OWNER' })` |
| `get`    | `await acl.get({ entity: 'user-person@example.com' })`                   |
| `delete` | `await acl.delete({ entity: 'user-person@example.com' })`                |

Each role group—`acl.readers`, `acl.writers`, and `acl.owners`—offers the same conveniences. Choose a role allowed for the resource; object ACLs do not allow WRITER.

| Method                                                     | Usage                                                                                                    |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `addAllUsers` / `deleteAllUsers`                           | `await acl.readers.addAllUsers()` / `await acl.readers.deleteAllUsers()`                                 |
| `addAllAuthenticatedUsers` / `deleteAllAuthenticatedUsers` | `await acl.readers.addAllAuthenticatedUsers()` / `await acl.readers.deleteAllAuthenticatedUsers()`       |
| `addUser` / `deleteUser`                                   | `await acl.writers.addUser('person@example.com')` / `await acl.writers.deleteUser('person@example.com')` |
| `addGroup` / `deleteGroup`                                 | `await acl.readers.addGroup('team@example.com')` / `await acl.readers.deleteGroup('team@example.com')`   |
| `addDomain` / `deleteDomain`                               | `await acl.readers.addDomain('example.com')` / `await acl.readers.deleteDomain('example.com')`           |
| `addProject` / `deleteProject`                             | `await acl.owners.addProject('owners', '123456')` / `await acl.owners.deleteProject('owners', '123456')` |

For defaults on future objects, use the same operations on `bucket.acl.default`, for example `await bucket.acl.default.readers.addUser('person@example.com')`.
