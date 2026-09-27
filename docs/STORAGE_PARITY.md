# Storage API compatibility

The public object model follows Firebase Admin Storage: `storage.bucket().file(name)`. Async operations retain this package's `{ error, data }` convention. Existing flat `storage.upload(name, ...)` and other REST-oriented methods remain available for compatibility.

The reference surface was compared with the official [Firebase Admin Storage API](https://firebase.google.com/docs/reference/admin/node/firebase-admin.storage) and the [Cloud Storage Bucket](https://cloud.google.com/nodejs/docs/reference/storage/latest/storage/bucket) and [File](https://cloud.google.com/nodejs/docs/reference/storage/latest/storage/file) APIs used by Admin.

| Surface                     | Implemented methods                                                                                                                                                                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Storage access              | `getStorage(server)`, `storage.bucket(name?)`                                                                                                                                                                                                           |
| Bucket references           | `file`, `notification`, `getId`, `get`, `create`, `exists`, `getMetadata`, `setMetadata`, `delete`, `restore`                                                                                                                                           |
| Bucket objects              | `getFiles`, `getFilesStream`, `upload`, `deleteFiles`, `combine`                                                                                                                                                                                        |
| Bucket administration       | `addLifecycleRule`, `getLabels`, `setLabels`, `deleteLabels`, `setCorsConfiguration`, `setStorageClass`, `setRetentionPeriod`, `removeRetentionPeriod`, `lock`, `enableRequesterPays`, `disableRequesterPays`, `enableLogging`, `setUserProject`        |
| Bucket access/events        | `getSignedUrl`, `makePublic`, `makePrivate`, `createNotification`, `getNotifications`, `createChannel`, `request`, `acl`, `acl.default`, `iam`                                                                                                          |
| File objects                | `get`, `exists`, `getMetadata`, `setMetadata`, `download`, `createReadStream`, `createWriteStream`, `save`, `createResumableUpload`, `delete`, `copy`, `move`, `rename`, `moveFileAtomic`, `restore`                                                    |
| File access/configuration   | `getSignedUrl`, `generateSignedPostPolicyV2`, `generateSignedPostPolicyV4`, `isPublic`, `publicUrl`, `makePublic`, `makePrivate`, `getExpirationDate`, `rotateEncryptionKey`, `setEncryptionKey`, `setStorageClass`, `setUserProject`, `request`, `acl` |
| Firebase helper and aliases | Standalone `getDownloadURL(file)`, `file.getDownloadURL()`, `file.stream()`, `file.upload()`                                                                                                                                                            |
| Supporting resources        | ACL CRUD and entity role helpers; IAM policy/permission methods; Notification and HmacKey metadata/existence/deletion methods; HmacKey state changes; Channel stop                                                                                      |

This is method-surface compatibility with documented edge adaptations, **not a drop-in replacement for every Node SDK option or callback overload**:

- `getStorage` requires this package's configured server; there is no global Firebase Admin app registry.
- Async results use named data directly instead of Node SDK tuple results. Listing returns `{ files, prefixes, nextQuery? }` inside `data`; downloads return Uint8Array.
- Reference factories, setters and URL getters remain synchronous. Invalid factory inputs throw. Streaming uses native Web Streams; errors during reads/writes follow Web Stream semantics. Writable streams also expose a `{ error, data }` completion promise.
- Local filesystem paths, Node Buffer-specific methods, EventEmitter streams, and callbacks are unavailable. Upload bytes, Blob, browser File, or ReadableStream instead.
- Checksum validation supports CRC32C, MD5, `true` (CRC32C), and `false`. MD5 uses incremental web-compatible hashing. MD5 is unavailable for objects such as composites that do not have a server MD5; validation returns `storage/checksum-unavailable`. Fetch owns HTTP decompression; disabling it is unsupported.
- Bucket logging provisions log-delivery IAM on the destination before updating configuration. It preserves existing grants, conditions, and etags, and retries IAM concurrency conflicts. Legacy webhook channels still depend on Google's service support and verification.
- IAM, ACLs, public access, object holds, retention locking, atomic moves, soft-delete restoration, and notifications depend on bucket settings and account permissions. The client cannot bypass server restrictions.

Signed URLs use absolute expiration, V2 by default, with V4 and POST policy signing available. Customer-supplied AES-256 keys, KMS destination keys, requester-pays billing, object generations, and generation preconditions are supported through reference options.

Additional option coverage includes per-call `userProject`, numeric reference preconditions/generations, predefined ACLs, primitive custom metadata, suffix byte ranges, listing `fields` and folder controls, soft-deleted reads/restore tokens, `get({ autoCreate: true })`, bucket `ignoreNotFound`, IAM policy versions, upload `timeout`, `highWaterMark`, `onUploadProgress`, `gzip: 'auto'`, `uri`, `offset`, and `resumeCRC32C`. Sliced resumptions require the preceding CRC32C when validation is enabled; MD5 requires the complete source.

`isPartialUpload` is implemented on `save`, `createWriteStream` and `uploadStream`. Partial input must be a positive multiple of 256 KiB with an explicit `chunkSize`. Completion returns an unfinalized session checkpoint with offset and CRC32C in `data`; Web writable completion exposes it through `.result`. Automatic gzip and whole-object MD5 cannot be continued across separate partial operations. Low-level `uploadChunk`/`getUploadStatus` remain available.

Custom `crc32cGenerator` factories work on File and Bucket references and the low-level checksum/transfer APIs, including incremental Web Streams and combining a supplied resume CRC with a custom suffix CRC. Validators consume Uint8Array rather than requiring Node Buffer.

The resource-option audit also added bucket `action: 'list'` signing, inherited bucket options, restore projections and top-level file preconditions, numeric compose/batch-delete guards, per-call encryption and resource billing, dual-region placement, hierarchical namespace creation, object retention enablement and metadata, bucket class/billing aliases, writable ACL metadata, and numeric retention periods. These options have mocked request/guard coverage; partial upload checkpoints and custom CRC resumptions also have live Storage coverage. This records the audited features rather than asserting that every future upstream option is covered.

Signing supports `host`, numeric/array extension headers, scalar query values, `${filename}` form policies, and explicit Google IAM `signingEndpoint` URLs. Local service-account signing remains the default. IAM signing reuses the configured credentials/cache/fetch and requires the corresponding IAM signing permission; it does not change authentication setup.

For projected listings, the client includes the name, bucket, generation, size, prefixes and next-page token needed to build references and continue pagination. Unsupported Node callback/transport hooks are not emulated; the exported TypeScript options define the accepted reference contract.

See [Bucket](BUCKET.md), [File](FILE.md), [ACL](ACL.md), [IAM](IAM.md), [Notification](NOTIFICATION.md), [HmacKey](HMAC_KEY.md), and [Channel](CHANNEL.md) for examples. Specialized REST methods—including managed folders and explicit resumable chunk/status operations—remain documented in [Storage](STORAGE.md).
