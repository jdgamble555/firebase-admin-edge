# Bucket

Notification and channel references returned by `createNotification()`,
`getNotifications()`, and `createChannel()` retain the supplied `userProject`
for later reads, deletions, and channel stops.

Cancelling `getFilesStream()` stops pagination even when a page request is already
in flight. The pending response is discarded when it arrives.

```ts
const bucket = firebaseServer.storage.bucket();
const otherBucket = firebaseServer.storage.bucket('another-bucket');
const file = bucket.file('documents/report.txt', { generation: '123' });

const { error, data } = await bucket.getFiles({ prefix: 'documents/' });
if (error) {
    throw error;
}
for (const entry of data.files) {
    console.log(entry.name, entry.metadata);
}
```

Factories are synchronous; async methods return `{ error, data }`. `getFiles` auto-paginates by default and returns `{ files, prefixes, nextQuery? }`. Use `autoPaginate: false` to make one request, then pass `data.nextQuery` to the next call. `maxApiCalls` bounds pagination. `versions` and `softDeleted` produce generation-specific File references.

| Method                  | Usage example                                                                                           | Successful data                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `getId`                 | `bucket.getId()`                                                                                        | Bucket name, synchronously                                 |
| `file`                  | `bucket.file('report.txt')`                                                                             | File reference, synchronously                              |
| `exists`                | `await bucket.exists()`                                                                                 | Boolean                                                    |
| `get`                   | `await bucket.get({ autoCreate: true, location: 'US' })`                                                | This reference                                             |
| `create`                | `await bucket.create({ location: 'US' })`                                                               | This reference                                             |
| `getMetadata`           | `await bucket.getMetadata()`                                                                            | Bucket metadata                                            |
| `setMetadata`           | `await bucket.setMetadata({ versioning: { enabled: true } })`                                           | Updated metadata                                           |
| `delete`                | `await bucket.delete({ ifMetagenerationMatch: '2' })`                                                   | `undefined`; bucket must be empty                          |
| `getFiles`              | `await bucket.getFiles({ autoPaginate: false, maxResults: 100 })`                                       | Files, prefixes and next query                             |
| `upload`                | `await bucket.upload(new Blob(['Hello']), { destination: 'hello.txt' })`                                | Uploaded File                                              |
| `deleteFiles`           | `await bucket.deleteFiles({ prefix: 'temporary/', force: true })`                                       | `undefined`, or an error if any deletion failed            |
| `combine`               | `await bucket.combine(['part1', 'part2'], 'combined')`                                                  | Destination File                                           |
| `getLabels`             | `await bucket.getLabels()`                                                                              | Label map                                                  |
| `setLabels`             | `await bucket.setLabels({ environment: 'test' })`                                                       | Metadata                                                   |
| `deleteLabels`          | `await bucket.deleteLabels(['environment'])`                                                            | Metadata; omit argument to remove all labels               |
| `setCorsConfiguration`  | `await bucket.setCorsConfiguration([{ origin: ['https://example.com'], method: ['GET'] }])`             | Metadata                                                   |
| `setStorageClass`       | `await bucket.setStorageClass('STANDARD')`                                                              | Metadata                                                   |
| `setRetentionPeriod`    | `await bucket.setRetentionPeriod(3600)`                                                                 | Metadata                                                   |
| `removeRetentionPeriod` | `await bucket.removeRetentionPeriod()`                                                                  | Metadata                                                   |
| `lock`                  | `await bucket.lock('2')`                                                                                | Metadata; irreversibly locks the retention policy          |
| `enableRequesterPays`   | `await bucket.enableRequesterPays()`                                                                    | Metadata                                                   |
| `disableRequesterPays`  | `await bucket.disableRequesterPays()`                                                                   | Metadata                                                   |
| `enableLogging`         | `await bucket.enableLogging({ bucket: 'log-bucket', prefix: 'logs/' })`                                 | Metadata; grants destination log-delivery permission first |
| `addLifecycleRule`      | `await bucket.addLifecycleRule({ action: { type: 'Delete' }, condition: { age: 30 } })`                 | Metadata; appends unless `append: false`                   |
| `restore`               | `await bucket.restore({ generation: '123' })`                                                           | Restored Bucket                                            |
| `createNotification`    | `await bucket.createNotification('projects/project/topics/topic', { eventTypes: ['OBJECT_FINALIZE'] })` | Notification reference                                     |
| `getNotifications`      | `await bucket.getNotifications()`                                                                       | Notification references                                    |
| `notification`          | `bucket.notification('1')`                                                                              | Notification reference, synchronously                      |
| `createChannel`         | `await bucket.createChannel('channel-id', { address: 'https://example.com/storage-events' })`           | Legacy Channel reference                                   |
| `makePublic`            | `await bucket.makePublic({ includeFiles: true })`                                                       | Affected File references                                   |
| `makePrivate`           | `await bucket.makePrivate({ includeFiles: true })`                                                      | Affected File references                                   |
| `getSignedUrl`          | `await bucket.getSignedUrl({ action: 'read', version: 'v4', expires: Date.now() + 300000 })`            | Signed URL                                                 |
| `setUserProject`        | `bucket.setUserProject('billing-project')`                                                              | This reference, synchronously                              |
| `request`               | `await bucket.request({ method: 'GET' })`                                                               | JSON response                                              |

`bucket.upload` accepts web bytes, Blob, File, and ReadableStream; a browser File supplies the default destination name. Local filesystem paths return `storage/unsupported-operation`. Use `bucket.file(name).save(text)` to upload a string.

`getFilesStream` is a lazy Web Stream, with cancellation and pagination limits:

```ts
const reader = bucket
    .getFilesStream({ prefix: 'documents/', maxApiCalls: 10 })
    .getReader();
try {
    for (;;) {
        const { done, value } = await reader.read();
        if (done) {
            break;
        }
        console.log(value.name);
    }
} finally {
    await reader.cancel();
    reader.releaseLock();
}
console.log(bucket.name, bucket.cloudStorageURI.toString());
```

See [File](FILE.md), [ACL and default ACL](ACL.md), [IAM](IAM.md), [Notification](NOTIFICATION.md), [Channel](CHANNEL.md), and [Storage parity](STORAGE_PARITY.md).

## Logging and additional options

`enableLogging({ prefix, bucket? })` grants `group:cloud-storage-analytics@google.com` the `roles/storage.objectCreator` role on the destination bucket, then enables logging on the source. The destination defaults to the current bucket. Existing IAM grants, conditions, and etags are preserved. A permission error prevents the source configuration update; if the configuration update fails after the grant succeeds, the error is returned and the narrow log-delivery grant remains.

```ts
const { error } = await bucket.enableLogging({
    bucket: 'log-destination',
    prefix: 'access/',
    ifMetagenerationMatch: 2
});
if (error) {
    throw error;
}
```

Projected listing and folder options work with the existing result shape:

```ts
const { error, data } = await bucket.getFiles({
    autoPaginate: false,
    delimiter: '/',
    includeFoldersAsPrefixes: true,
    includeTrailingDelimiter: true,
    fields: 'items(contentType,md5Hash)',
    userProject: 'billing-project'
});
if (error) {
    throw error;
}
console.log(data.files, data.prefixes, data.nextQuery);
```

The client adds identity and pagination fields to projected listings. `await bucket.exists({ userProject: 'billing-project' })` and `await bucket.delete({ ignoreNotFound: true })` retain `{ error, data }`. Label deletion accepts concurrency options, for example `await bucket.deleteLabels(['environment'], { ifMetagenerationMatch: 2 })`.

## Additional SDK options

Bucket references accept inherited checksum, KMS, billing and precondition options. `generation` and `softDeleted` select bucket metadata; they are not inherited as object generations.

```ts
const bucket = storage.bucket('my-bucket', {
    userProject: 'billing-project',
    crc32cGenerator,
    kmsKeyName,
    preconditionOpts: { ifMetagenerationMatch: 2 }
});
const { error, data } = await bucket.getSignedUrl({
    action: 'list',
    version: 'v4',
    expires: Date.now() + 300000,
    queryParams: { prefix: 'photos/' }
});
if (error) {
    throw error;
}
```

Creation supports dual-region placement, hierarchical namespaces, object retention enablement, predefined ACLs, projection, requester-pays billing and storage-class aliases. Configuration support still depends on the selected region and Google Cloud service constraints. Object retention enablement is permanent.

```ts
const { error } = await storage.bucket('new-unique-bucket').create({
    location: 'US',
    dataLocations: ['US-EAST1', 'US-WEST1'],
    standard: true,
    requesterPays: true,
    projection: 'full',
    userProject: 'billing-project'
});
if (error) {
    throw error;
}
```

Use `customPlacementConfig: { dataLocations }` instead of the `dataLocations` alias if preferred. Creation also accepts `hierarchicalNamespace: { enabled: true }` and `enableObjectRetention: true`. Storage-class aliases are `standard`, `nearline`, `coldline`, `archive`, `regional`, `multiRegional`, and `dra`; contradictory class selections return an error. `rpo`, writable `acl`/`defaultObjectAcl`, and numeric retention/soft-delete periods are supported in bucket settings.

```ts
const { error: labelsError, data: labels } = await bucket.getLabels({
    userProject: 'billing-project'
});
const { error: combineError } = await bucket.combine(
    ['part1', 'part2'],
    'combined',
    { ifGenerationMatch: 0 }
);
const { error: deleteError } = await bucket.deleteFiles({
    prefix: 'temporary/',
    ifGenerationMatch: 123
});
const { error: restoreError } = await bucket.restore({
    generation: '123',
    projection: 'full'
});
const { error: uploadError } = await bucket.upload(bytes, {
    destination: 'encrypted.bin',
    encryptionKey
});
const { error: notificationsError } = await bucket.getNotifications({
    userProject: 'billing-project'
});
const { error: notificationError } = await bucket.createNotification(
    'projects/project/topics/topic',
    { userProject: 'billing-project' }
);
const { error: channelError } = await bucket.createChannel(
    'channel-id',
    { address: 'https://example.com/webhook' },
    { userProject: 'billing-project' }
);
```
