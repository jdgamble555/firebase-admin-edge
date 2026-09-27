# Storage

[Back to the README](../README.md)

`Storage` provides Firebase Admin-style bucket/file references through the
[Cloud Storage JSON API](https://docs.cloud.google.com/storage/docs/json_api/v1).
It uses service-account IAM permissions, so authorize callers in your server
before exposing these operations. Firebase Storage client security rules do not
authorize these admin requests.

## Admin-style references

```ts
const bucket = firebaseServer.storage.bucket();
const file = bucket.file('notes/hello.txt');
const { error } = await file.save('Hello!', {
    metadata: { contentType: 'text/plain' }
});
if (error) {
    throw error;
}
```

Use the [Bucket](BUCKET.md) and [File](FILE.md) guides for the public reference API,
and [Storage parity](STORAGE_PARITY.md) for the complete method checklist and edge
adaptations. Reference factories do not make requests; async operations retain
`{ error, data }`. Invalid synchronous factory inputs throw.

`storage.bucket('another-bucket')` binds a reference to another bucket.
`storage.hmacKey(accessId)` creates an [HmacKey](HMAC_KEY.md) reference.
The flat methods below remain available as lower-level operations.

## Setup

```ts
import { Storage } from 'firebase-admin-edge';

const storage = new Storage(
    serviceAccount,
    'your-project.firebasestorage.app', // Use the actual bucket name.
    fetch, // Optional custom fetch.
    cache, // Optional package CacheConfig.
    'my-app' // Optional cache key prefix.
);
```

Alternatively, set `firebaseConfig.storageBucket` when creating the edge server
and use `firebaseServer.storage`. No bucket name is inferred from the project ID;
a missing bucket returns `storage/invalid-argument` when an operation is called.
Use `storage.bucket(name)` to work with another bucket.

Each async method returns `{ error, data }`. On failure `data` is `null` and
`error` is a `FirebaseEdgeError`. Service-account token errors retain their codes.
Storage errors include `storage/invalid-argument`, `storage/object-not-found`,
`storage/permission-denied`, and `storage/precondition-failed`. A partially
completed move returns `storage/move-incomplete` with recovery details.

## upload(name, body, options?)

Accepts a string, `Blob` (including `File`), `ArrayBuffer`, or `Uint8Array` backed
by an `ArrayBuffer`. Empty files are supported. Returns object metadata. Uses
`options.contentType`, the Blob's MIME type, or `application/octet-stream`.

```ts
const { error, data } = await storage.upload('notes/hello.txt', 'Hello!', {
    contentType: 'text/plain; charset=utf-8',
    ifGenerationMatch: '0'
});
if (error) {
    throw error;
}
console.log(data.name, data.generation);
```

`ifGenerationMatch: '0'` requires a new object. Omit it to allow replacement, or
pass the existing generation string to replace only that version. Generation
numbers and sizes remain strings to preserve integer precision.

## download(name, options?)

Returns file contents as a `Uint8Array`. The complete file is buffered in memory.
Use `downloadStream` for larger files. Both methods accept `generation`, inclusive
byte offsets `start` / `end`, and generation/metageneration preconditions.

```ts
const { error, data } = await storage.download('notes/hello.txt');
if (error) {
    throw error;
}
return new Response(data, { headers: { 'Content-Type': 'text/plain' } });
```

## getMetadata(name, options?)

```ts
const { error, data } = await storage.getMetadata('notes/hello.txt');
if (error) {
    throw error;
}
console.log(data.contentType, data.size, data.generation);
```

## delete(name, options?)

Successful deletion returns `{ error: null, data: undefined }`. A missing object
returns `storage/object-not-found`.

```ts
const { error } = await storage.delete('notes/hello.txt', {
    ifGenerationMatch: generation // From upload or getMetadata.
});
if (error) {
    throw error;
}
```

## listFiles(options?)

Returns one page with `files`, `prefixes`, and an optional `nextPageToken`.
`maxResults` must be an integer from 1 to 1000. Pass `delimiter: '/'` to group
nested object names into prefixes. Continue while a token is present, even when
the current page has no files.

```ts
let pageToken: string | undefined;
do {
    const { error, data } = await storage.listFiles({
        prefix: 'notes/',
        maxResults: 100,
        pageToken
    });
    if (error) {
        throw error;
    }
    console.log(data.files, data.prefixes);
    pageToken = data.nextPageToken;
} while (pageToken);
```

## getSignedUrl(name, options)

Creates a [V4 signed URL](https://docs.cloud.google.com/storage/docs/access-control/signing-urls-manually)
locally using the service account private key and Web Crypto. No OAuth or
Storage request is made. `action: 'read'` signs a GET download and `action: 'write'`
signs a PUT upload. `expiresInSeconds` defaults to 900 (15 minutes) and accepts
integers from 1 to 604800 (7 days).

```ts
const { error, data: downloadUrl } = await storage.getSignedUrl(
    'notes/hello.txt',
    {
        action: 'read',
        expiresInSeconds: 300
    }
);
if (error) {
    throw error;
}
// Send downloadUrl to the authorized caller.
```

```ts
const { error, data: uploadUrl } = await storage.getSignedUrl('notes/new.txt', {
    action: 'write',
    expiresInSeconds: 300,
    contentType: 'text/plain'
});
if (error) {
    throw error;
}
// The recipient uploads the raw file body with this method and header.
const response = await fetch(uploadUrl, {
    method: 'PUT',
    headers: { 'Content-Type': 'text/plain' },
    body: 'Hello!'
});
if (!response.ok) {
    throw new Error(`Upload failed: ${response.status}`);
}
```

Anyone holding the URL can perform the signed operation until it expires.
The service account must have the corresponding object permissions. Write URLs
allow replacement of existing objects. When supplied, `contentType` is signed
and must accompany the upload; it is only accepted for write URLs. Browser
uploads also require appropriate bucket CORS configuration. Object names with
`.` or `..` path segments are rejected because URL clients normalize them.

## updateMetadata(name, metadata, options?)

Patches content type, cache control, content disposition, content encoding,
content language, or custom metadata and returns the updated object metadata.
Only supplied fields change. A `null` value removes a field or custom metadata
key; `metadata: null` removes all custom metadata. The update must be nonempty.
Use `ifGenerationMatch` and `ifMetagenerationMatch` to guard concurrent changes.

```ts
const { error, data } = await storage.updateMetadata(
    'notes/hello.txt',
    {
        contentType: 'text/plain; charset=utf-8',
        cacheControl: 'private, max-age=300',
        metadata: { category: 'notes', oldLabel: null }
    },
    {
        ifMetagenerationMatch: metageneration // From getMetadata.
    }
);
if (error) {
    throw error;
}
console.log(data.metageneration);
```

## exists(name, options?)

Returns `true` when metadata can be read and `false` for an object-not-found
response. Permission, authentication, and network failures remain errors.

```ts
const { error, data: exists } = await storage.exists('notes/hello.txt');
if (error) {
    throw error;
}
console.log(exists);
```

## copy(name, destination, options?)

Copies an object within the configured bucket or into `destinationBucket` and
returns the destination metadata. Uses the
[rewrite API](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/rewrite)
and follows continuation tokens without downloading file contents. Source and
destination must be different objects. Metadata is preserved by the server.

```ts
const { error, data } = await storage.copy(
    'notes/hello.txt',
    'backup/hello.txt',
    {
        destinationBucket: 'my-backup-bucket', // Omit for the current bucket.
        ifGenerationMatch: '0', // Require a new destination object.
        ifSourceGenerationMatch: generation // Optional source guard from getMetadata.
    }
);
if (error) {
    throw error;
}
console.log(data.bucket, data.name);
```

Omitting `ifGenerationMatch` permits overwriting the destination. Both generation
preconditions use strings, as with upload and delete.

## move(name, destination, options?)

Accepts the same options as `copy`. Reads the source generation, copies it, and
deletes the source only if its generation still matches. This supports moves
between buckets and renames within a bucket. The operation is **not atomic**.

```ts
const { error, data } = await storage.move(
    'notes/hello.txt',
    'archive/hello.txt',
    {
        ifGenerationMatch: '0'
    }
);
if (error) {
    if (error.code === 'storage/move-incomplete') {
        // The copy succeeded. Inspect these details before retrying or cleaning up.
        console.error(error.context, error.cause);
    }
    throw error;
}
console.log(data.name);
```

If the source read or copy fails, no deletion is attempted. If deletion fails,
the destination copy is kept. `storage/move-incomplete` includes source and
destination bucket names, object names, and generations in `error.context`,
with the deletion error in `error.cause`. No automatic rollback is attempted.

## downloadStream(name, options?)

Returns a Fetch `Response` without buffering its body. Forward it from an edge
handler, or consume `data.body` as a web `ReadableStream`. Status and headers
(including `Content-Range`, MIME type, and cache control) are preserved. The caller
must consume or cancel the body. Errors while consuming the stream occur after
the method's result has been returned.

```ts
const { error, data } = await storage.downloadStream('videos/demo.mp4', {
    start: 0,
    end: 1048575 // Inclusive; omit end to read through EOF.
});
if (error) {
    throw error;
}
return data;
```

## Resumable uploads

These methods implement the [Cloud Storage resumable upload protocol](https://docs.cloud.google.com/storage/docs/performing-resumable-uploads)
with web-native bodies. The session URI can be stored between separate edge
requests; the library does not depend on a process staying alive. Treat it as a
secret: possession authorizes uploading without another OAuth token. Only Google
Storage upload-session URLs are accepted, and session requests do not follow
redirects.

### createResumableUpload(name, options?)

Returns the session URI. Options include `contentType`, `size` (known total bytes),
`metadata`, and upload preconditions. Omit `size` when the final length is unknown.

```ts
const { error, data: sessionUri } = await storage.createResumableUpload(
    'videos/new.mp4',
    {
        contentType: 'video/mp4',
        size: file.size, // file is a Blob/File.
        metadata: { metadata: { category: 'demo' } },
        ifGenerationMatch: '0'
    }
);
if (error) {
    throw error;
}
// Store sessionUri securely for subsequent chunk requests.
```

### uploadChunk(sessionUri, body, { offset, totalSize? })

Accepts the same body types as `upload`. `offset` and `totalSize` are byte counts,
represented as nonnegative safe integers. Non-final chunks must be positive
multiples of 256 KiB. Set `totalSize` on the final chunk; omit it for intermediate
chunks when the total length is unknown. Empty files use `offset: 0, totalSize: 0`.

```ts
const chunk = file.slice(offset, offset + 8 * 1024 * 1024);
const { error, data } = await storage.uploadChunk(sessionUri, chunk, {
    offset,
    totalSize: file.size
});
if (error) {
    throw error;
}
if (data.complete) {
    console.log(data.metadata.name);
} else {
    // Persist this server-confirmed offset for the next request.
    console.log(data.nextOffset);
}
```

### getUploadStatus(sessionUri, totalSize?)

After a timeout or connection failure, probe the session before resending data.
Use the returned `nextOffset`, which may differ from the number of bytes sent.
The return shape matches `uploadChunk`.

```ts
const { error, data } = await storage.getUploadStatus(sessionUri, file.size);
if (error) {
    throw error;
}
if (!data.complete) {
    console.log('Resume at byte', data.nextOffset);
}
```

### cancelUpload(sessionUri)

```ts
const { error } = await storage.cancelUpload(sessionUri);
if (error) {
    throw error;
}
```

Retries and persistent session storage are caller-controlled, so requests fit the
runtime's duration and memory limits. No local filesystem or Node streams are used.

## Object versions and preconditions

`download`, `downloadStream`, `getMetadata`, `exists`, `updateMetadata`, and `delete`
accept a `generation` string to select a specific object version. Mutations and
reads support `ifGenerationMatch`, `ifGenerationNotMatch`,
`ifMetagenerationMatch`, and `ifMetagenerationNotMatch` where the API permits them.
Google validates the combination of conditions for each operation.

`listFiles({ versions: true })` includes noncurrent versions.
`listFiles({ softDeleted: true })` lists soft-deleted objects instead; those two
flags cannot both be true. Listing also accepts `startOffset`, `endOffset`, and
`matchGlob` for server-side filtering. Pagination still returns one page at a time.

```ts
const { error, data } = await storage.listFiles({
    prefix: 'notes/',
    versions: true
});
if (error) {
    throw error;
}
console.log(data.files.map(({ name, generation }) => ({ name, generation })));
```

`copy` and `move` accept `sourceGeneration` to select a source version, and
`ifSourceGenerationMatch` / `ifSourceMetagenerationMatch` to guard the source.
Copying an older version to the same name can restore it as the live version:

```ts
const { error, data } = await storage.copy(
    'notes/hello.txt',
    'notes/hello.txt',
    {
        sourceGeneration: oldGeneration,
        ifGenerationMatch: currentGeneration
    }
);
if (error) {
    throw error;
}
console.log(data.generation);
```

Moves always require distinct source and destination objects, even when selecting
a source version. They delete only the selected version after a successful copy.

### restore(name, options)

Restores a soft-deleted object by `generation`. The bucket must have soft delete
enabled and the object must still be within its retention window. Supply
`restoreToken` when the listed soft-deleted object requires it. `copySourceAcl`
and destination preconditions are optional.

```ts
const { error, data } = await storage.restore('notes/deleted.txt', {
    generation: deletedGeneration,
    ifGenerationMatch: '0'
});
if (error) {
    throw error;
}
console.log(data.generation);
```

## compose(destination, sources, options?)

Combines 1–32 objects in the current bucket on the server, without downloading
their contents. Each source accepts an optional `generation` and
`objectPreconditions: { ifGenerationMatch }`. Options accept destination
preconditions and destination `metadata`.

```ts
const { error, data } = await storage.compose(
    'joined.txt',
    [
        { name: 'part-1.txt', generation: firstGeneration },
        { name: 'part-2.txt' }
    ],
    { ifGenerationMatch: '0', metadata: { contentType: 'text/plain' } }
);
if (error) {
    throw error;
}
console.log(data.size);
```

## deleteFiles(targets, options?)

Deletes an explicit array of names or `{ name, generation?, ...preconditions }`
objects. Validates the entire batch before starting. `concurrency` defaults to 5
and accepts integers from 1 to 32. `ignoreNotFound` defaults to false.

The outer result reports validation failures. Once deletion begins, each target
has its own `error` in `data.results`, in input order. Other targets continue when
one fails. This is bounded parallel deletion, not an atomic transaction.

```ts
const { error, data } = await storage.deleteFiles(
    ['temporary/a.txt', { name: 'temporary/b.txt', generation }],
    { concurrency: 4, ignoreNotFound: true }
);
if (error) {
    throw error;
}
for (const { name, error: fileError } of data.results) {
    if (fileError) {
        console.error(name, fileError.code);
    }
}
```

## Bucket administration

These methods operate on the instance's `bucketName`, except `listBuckets`, which
lists the service account's project. They require the corresponding bucket IAM
permissions. Create a separate `Storage` instance to administer another bucket.
These APIs manage Google Cloud Storage buckets; creation does not automatically
provision Firebase client rules or register an additional bucket with Firebase.

### getBucketMetadata(options?)

```ts
const { error, data } = await storage.getBucketMetadata();
if (error) {
    throw error;
}
console.log(data.location, data.cors, data.lifecycle, data.metageneration);
```

### updateBucketMetadata(metadata, options?)

Supports CORS, lifecycle rules, versioning, labels, default storage class,
event-based holds, requester pays, default KMS encryption, retention period,
soft-delete retention, uniform bucket-level access, public access prevention,
and Autoclass. Nested service-specific constraints are checked by Google.
Lifecycle and CORS updates replace their configurations; empty arrays clear them.
Use `ifMetagenerationMatch` to protect against concurrent changes.

```ts
const { error, data } = await storage.updateBucketMetadata(
    {
        cors: [
            {
                origin: ['https://example.com'],
                method: ['GET', 'PUT'],
                responseHeader: ['Content-Type'],
                maxAgeSeconds: 3600
            }
        ],
        lifecycle: {
            rule: [
                {
                    action: { type: 'Delete' },
                    condition: { age: 30, matchesPrefix: ['temporary/'] }
                }
            ]
        },
        versioning: { enabled: true }
    },
    { ifMetagenerationMatch: bucketMetageneration }
);
if (error) {
    throw error;
}
console.log(data.metageneration);
```

### createBucket(metadata)

Creates the configured bucket in the service account's project. `location` is
required; the remaining settings match `updateBucketMetadata`.

```ts
const newBucket = new Storage(serviceAccount, 'my-globally-unique-bucket');
const { error, data } = await newBucket.createBucket({
    location: 'US',
    iamConfiguration: { uniformBucketLevelAccess: { enabled: true } }
});
if (error) {
    throw error;
}
console.log(data.name);
```

### listBuckets(options?)

Returns one page of `buckets` and optional `nextPageToken`. Accepts `prefix`,
`pageToken`, and `maxResults` (1–1000); repeat with the returned token.

```ts
const { error, data } = await storage.listBuckets({
    prefix: 'my-',
    maxResults: 100
});
if (error) {
    throw error;
}
console.log(data.buckets, data.nextPageToken);
```

### deleteBucket(options?)

Deletes the configured bucket only if the service permits it (in particular,
the bucket must be empty). It does not recursively delete objects.

```ts
const { error } = await newBucket.deleteBucket({
    ifMetagenerationMatch: bucketMetageneration
});
if (error) {
    throw error;
}
```

### getIamPolicy() and setIamPolicy(policy)

Reads policy version 3 so conditional bindings are preserved. Setting a policy
replaces its bindings; preserve the fetched `etag` to detect concurrent updates.
Conditional bindings require `version: 3`.

```ts
const { error: readError, data: policy } = await storage.getIamPolicy();
if (readError) {
    throw readError;
}
const { error, data } = await storage.setIamPolicy({
    ...policy,
    bindings: [
        ...policy.bindings,
        {
            role: 'roles/storage.objectViewer',
            members: [
                'serviceAccount:reader@example-project.iam.gserviceaccount.com'
            ]
        }
    ]
});
if (error) {
    throw error;
}
console.log(data.etag);
```

### testIamPermissions(permissions)

Returns the subset of requested permissions held by the service account on the
bucket. An empty returned array means none of them were granted.

```ts
const { error, data } = await storage.testIamPermissions([
    'storage.objects.get',
    'storage.objects.create'
]);
if (error) {
    throw error;
}
console.log(data);
```

## Retries, checksums, and upload progress

Storage retries transient read failures and guarded writes with bounded exponential
backoff. Defaults are two additional attempts, a 100 ms initial delay, and a
2 second maximum delay. `Retry-After` is honored within that bound. Configure the
sixth constructor argument; `maxRetries: 0` disables retries:

```ts
const storage = new Storage(
    serviceAccount,
    bucketName,
    fetch,
    cache,
    undefined,
    {
        maxRetries: 3,
        initialDelayMs: 200,
        maxDelayMs: 3000
    }
);
```

Only replayable requests to the Storage API are retried. GET/HEAD, resumable status
probes, and appropriately guarded mutations qualify. Unguarded writes, session
creation, chunk uploads, IAM replacements, and HMAC creation are not automatically
retried. Probe a resumable session after an uncertain chunk result before resending
bytes. A guarded write can succeed before a connection fails and subsequently
return a precondition error; read the resource to reconcile that outcome.
See Google's [retry guidance](https://docs.cloud.google.com/storage/docs/retry-strategy).

`upload` accepts `crc32c: 'auto'` or a precomputed base64 CRC32C. Checked uploads
use multipart metadata for server validation and also compare the returned checksum.
`download` accepts `verifyChecksum: true` for full buffered
downloads. Missing checksums, encoded responses, and mismatched bytes produce
errors. Streaming verification is also supported; partial range responses cannot
be checked against a whole-object checksum.

```ts
const { error: uploadError } = await storage.upload('checked.txt', 'hello', {
    crc32c: 'auto',
    ifGenerationMatch: '0',
    onProgress: ({ bytesTransferred, totalBytes, complete }) => {
        console.log(bytesTransferred, totalBytes, complete);
    }
});
if (uploadError) {
    throw uploadError;
}
const { error, data } = await storage.download('checked.txt', {
    verifyChecksum: true
});
if (error) {
    throw error;
}
console.log(data);
```

Progress callbacks report **server-acknowledged bytes**, once per successful upload
request or chunk. They do not report socket-level progress. Async callbacks are
awaited; a thrown callback produces `storage/progress-callback-failed` even though
the server has already accepted the bytes. It does not roll back the upload.

Resumable uploads accept a **whole-object** CRC32C in the session metadata or on
the final chunk. Supply it in the session metadata for validation before commit.
The final-chunk option sends the checksum header and verifies returned metadata;
if the service accepts a mismatched upload, the method returns an error containing
the object's name and generation in `error.context`. The object is not automatically
deleted. Compute the checksum before splitting the input; never pass an individual
chunk's checksum as the object checksum:

```ts
import { calculateStorageCrc32c } from 'firebase-admin-edge';

const bytes = new Uint8Array(262147);
const crc32c = await calculateStorageCrc32c(bytes);
const { error: startError, data: session } =
    await storage.createResumableUpload('checked.bin', {
        size: bytes.length,
        crc32c
    });
if (startError) {
    throw startError;
}
const { error: firstError } = await storage.uploadChunk(
    session,
    bytes.slice(0, 262144),
    {
        offset: 0,
        totalSize: bytes.length,
        onProgress: ({ bytesTransferred }) => console.log(bytesTransferred)
    }
);
if (firstError) {
    throw firstError;
}
const { error } = await storage.uploadChunk(session, bytes.slice(262144), {
    offset: 262144,
    totalSize: bytes.length,
    crc32c,
    onProgress: ({ complete }) => console.log(complete)
});
if (error) {
    throw error;
}
```

## Notification configurations

Create, list, read, and delete Cloud Storage Pub/Sub notification configurations.
The topic must already exist and allow the Storage service agent to publish.
These methods manage configurations; they do not create topics or subscribe to
messages. Resource fields use Google's JSON API names.

```ts
const { error: createError, data: notification } =
    await storage.createNotification({
        topic: '//pubsub.googleapis.com/projects/my-project/topics/uploads',
        payload_format: 'JSON_API_V1',
        event_types: ['OBJECT_FINALIZE'],
        object_name_prefix: 'uploads/',
        custom_attributes: { source: 'storage' }
    });
if (createError) {
    throw createError;
}
const { error: listError, data: page } = await storage.listNotifications();
if (listError) {
    throw listError;
}
console.log(page.items);
const { error: getError, data } = await storage.getNotification(
    notification.id
);
if (getError) {
    throw getError;
}
console.log(data.topic);
const { error } = await storage.deleteNotification(notification.id);
if (error) {
    throw error;
}
```

## Managed folders

Managed folders require uniform bucket-level access. Names end in `/`; they group
objects for IAM policy management. Listing returns one page, with `nextPageToken`
when more results exist. Deleting a managed folder does not delete its objects.
Set `allowNonEmpty: true` only when intentionally removing its policy boundary.

```ts
const { error: createError } = await storage.createManagedFolder('team/');
if (createError) {
    throw createError;
}
const { error: listError, data: page } = await storage.listManagedFolders({
    prefix: 'team/',
    maxResults: 100
});
if (listError) {
    throw listError;
}
console.log(page.items, page.nextPageToken);
const { error: getError, data: folder } =
    await storage.getManagedFolder('team/');
if (getError) {
    throw getError;
}
const { error } = await storage.deleteManagedFolder('team/', {
    ifMetagenerationMatch: folder.metageneration
});
if (error) {
    throw error;
}
```

Managed folder IAM reads request policy version 3. Preserve existing bindings and
the fetched `etag` when replacing a policy:

```ts
const { error: readError, data: policy } =
    await storage.getManagedFolderIamPolicy('team/');
if (readError) {
    throw readError;
}
const { error: writeError } = await storage.setManagedFolderIamPolicy('team/', {
    ...policy,
    bindings: [
        ...policy.bindings,
        {
            role: 'roles/storage.objectViewer',
            members: [
                'serviceAccount:reader@my-project.iam.gserviceaccount.com'
            ]
        }
    ]
});
if (writeError) {
    throw writeError;
}
const { error, data } = await storage.testManagedFolderIamPermissions('team/', [
    'storage.managedFolders.get'
]);
if (error) {
    throw error;
}
console.log(data);
```

## HMAC key administration

HMAC operations use the service account's `project_id` and do not require a bucket.
They manage keys for the Cloud Storage XML API; Storage's JSON requests continue
using OAuth. The secret is returned only by `createHmacKey`. Store it securely
before leaving that operation; do not log it. Keys must be inactive before deletion.

```ts
const { error: createError, data: key } = await storage.createHmacKey(
    'worker@my-project.iam.gserviceaccount.com'
);
if (createError) {
    throw createError;
}
await secretStore.put(key.metadata.accessId, key.secret);
const { error: listError, data: page } = await storage.listHmacKeys({
    serviceAccountEmail: key.metadata.serviceAccountEmail,
    showDeletedKeys: false,
    maxResults: 100
});
if (listError) {
    throw listError;
}
console.log(page.items, page.nextPageToken);
const { error: getError, data: metadata } = await storage.getHmacKey(
    key.metadata.accessId
);
if (getError) {
    throw getError;
}
const { error: updateError } = await storage.updateHmacKey(
    metadata.accessId,
    'INACTIVE',
    metadata.etag
);
if (updateError) {
    throw updateError;
}
const { error } = await storage.deleteHmacKey(metadata.accessId);
if (error) {
    throw error;
}
```

`secretStore` above is your application's secret-storage adapter. Key activation
and state changes can take time to propagate; these methods return the API result
and do not wait for global propagation.

## Legacy ACLs

ACL methods accept a target: `{ scope: 'bucket' }`, `{ scope: 'defaultObject' }`,
or `{ scope: 'object', name, generation? }`. They require fine-grained access;
uniform bucket-level access disables ACL operations. Object/default ACL roles are
`OWNER` or `READER`; bucket ACLs also allow `WRITER`. Default object ACLs affect
future objects. Prefer IAM for buckets using uniform access.

```ts
const target = { scope: 'object' as const, name: 'report.pdf' };
const entity = 'user-reader@example.com';
const { error: createError } = await storage.createAcl(target, {
    entity,
    role: 'READER'
});
if (createError) {
    throw createError;
}
const { error: listError, data: page } = await storage.listAcl(target);
if (listError) {
    throw listError;
}
console.log(page.items);
const { error: getError, data } = await storage.getAcl(target, entity);
if (getError) {
    throw getError;
}
console.log(data.role);
const { error: updateError } = await storage.updateAcl(target, {
    entity,
    role: 'OWNER'
});
if (updateError) {
    throw updateError;
}
const { error } = await storage.deleteAcl(target, entity);
if (error) {
    throw error;
}
```

## Verified streaming downloads

`downloadStream(name, { verifyChecksum: true })` computes CRC32C as the consumer
reads the body, preserving backpressure and cancellation. It does not buffer the
whole object. A checksum mismatch rejects the final body read, `pipeTo`, or
`response.arrayBuffer()` call. Missing headers and encoded/range responses fail
before a verified stream is returned.

```ts
const { error, data: response } = await storage.downloadStream('large.bin', {
    verifyChecksum: true
});
if (error) {
    throw error;
}
// destination is your WritableStream<Uint8Array>.
// A rejected pipe must be treated as an incomplete or corrupt download.
await response.body!.pipeTo(destination);
```

Verification succeeds only after the entire body reaches EOF. Bytes delivered
before that point have not yet passed the final integrity check. Cancellation
stops the download without asserting that its checksum matched.

## uploadStream(name, input, options?)

Uploads a `ReadableStream<Uint8Array>`, `Blob`, string, `ArrayBuffer`, or
`Uint8Array` through a resumable session. It splits input into aligned chunks,
probes the saved offset after transient failures, and retains bytes needed for
bounded recovery. Non-final retries can replay identical persisted overlap to
keep chunk lengths aligned; Google ignores those previously accepted bytes.

Defaults: 8 MiB chunks, two recovery attempts per chunk, and incremental CRC32C
verification. `chunkSize` must be a multiple of 256 KiB between 256 KiB and 64 MiB.
Memory includes the current chunk, one lookahead chunk, and the source's own
buffering. The source must produce byte chunks. For streams, `size` is optional;
for materialized data it is inferred. A supplied size must match the input.

```ts
let savedSession: string | undefined;
const { error, data } = await storage.uploadStream('large.bin', inputStream, {
    chunkSize: 8 * 1024 * 1024,
    maxResumeAttempts: 2,
    crc32c: 'auto',
    onSession: (session) => {
        savedSession = session;
    },
    onProgress: ({ bytesTransferred, totalBytes, complete }) => {
        console.log(bytesTransferred, totalBytes, complete);
    }
});
if (error) {
    throw error;
}
console.log(data.generation);
```

Persist the session through `onSession` to recover across requests or runtime
restarts. Treat the session URI as a write credential. To resume, provide the
same source **from byte zero**, not just the remaining bytes:

```ts
const { error, data } = await storage.uploadStream(
    'large.bin',
    reopenedStream,
    {
        sessionUri: savedSession,
        crc32c: 'auto'
    }
);
if (error) {
    throw error;
}
console.log(data.crc32c);
```

The helper skips already accepted bytes while calculating the checksum of the
complete source. Completed sessions are also checked against the supplied source.
`onProgress` is awaited and reports acknowledged bytes; callback failures do not
cause uploads to replay. Session creation is not retried. A failed call preserves
the session for recovery; call `cancelUpload` when abandoning it. Expired sessions
require starting again. Authentication, permission, precondition, and checksum
errors are returned immediately.

Automatic CRC32C is known only after reading the complete input, so final metadata
verification may detect corruption after the object was committed. Supply a
precomputed whole-object `crc32c` for server-side validation from session creation.
The helper never deletes a committed object on checksum failure.

## lockRetentionPolicy(ifMetagenerationMatch)

Irreversibly locks the configured bucket's existing retention policy. The current
positive metageneration is required; a concurrent bucket change causes a
precondition failure. A locked retention policy cannot be removed or shortened.
Only invoke this method when that permanent retention requirement is intended.
See [Google's bucket-lock documentation](https://docs.cloud.google.com/storage/docs/using-bucket-lock).

```ts
const { error: readError, data: bucket } = await storage.getBucketMetadata();
if (readError) {
    throw readError;
}
const { error, data } = await storage.lockRetentionPolicy(
    bucket.metageneration
);
if (error) {
    throw error;
}
console.log(data.retentionPolicy);
```

## signXmlRequest(options)

Creates a Fetch `Request` carrying a V4 RSA `Authorization` signature using this
Storage instance's service account. It does not send the request. Supports `GET`,
`HEAD`, `PUT`, `POST`, and `DELETE`, encoded object names, bucket-level requests,
custom headers, and query parameters. Send the returned request unchanged and
promptly; it has a timestamp and does not refresh credentials automatically.

```ts
const { error, data: request } = await storage.signXmlRequest({
    method: 'PUT',
    name: 'xml/example.txt',
    body: 'hello',
    headers: { 'Content-Type': 'text/plain' }
});
if (error) {
    throw error;
}
const response = await fetch(request);
if (!response.ok) {
    throw new Error(`XML upload failed (${response.status})`);
}
await response.body?.cancel();
```

Omit `name` for bucket-level requests. Bodies use the same materialized web types
as `upload` and are buffered to compute SHA-256; use `uploadStream` for large
streaming transfers. GET/HEAD bodies are rejected. The signer owns the authorization,
host, date, payload-hash, and content-length headers. Redirects are returned for
explicit handling instead of forwarding credentials. XML responses remain raw
Fetch responses. For HMAC credentials, use the standalone
[`signStorageXmlRequest`](FUNCTIONS.md#storage-xml-request-signing).

## Validation and scope

All production code uses Fetch, Web Crypto, and web-native data types. Unit tests
cover input guards, protocol details, and partial failures. Live tests cover
object operations. Opt-in administration tests create a dedicated temporary bucket
for settings, IAM, managed folders, and soft-delete restoration. See [integration testing](INTEGRATION_TESTING.md#storage)
for credentials and the test command.

Specialized live tests provision a temporary fine-grained bucket, HMAC key, and
private Pub/Sub topic to exercise notifications and legacy ACLs. A separate opt-in
flag tests a one-second retention lock on that disposable bucket. Streaming
checksums, automated resumption, and RSA XML requests also have live coverage.
Unit tests independently verify both RSA and HMAC signatures.

With the current test credentials, ACL and retention-lock live tests pass.
HMAC and notification live tests are implemented but blocked by missing
`storage.hmacKeys.create` and `pubsub.topics.create` permissions. They remain
failures when explicitly enabled; they are not counted as successful live coverage.

`uploadStream()` also supports `isPartialUpload: true`, returning a checkpoint instead of completed metadata. See [File partial uploads](FILE.md#partial-uploads-and-custom-crc32c) for Web writable and custom checksum examples.

```ts
const { error, data: checkpoint } = await storage.uploadStream(
    'large.bin',
    firstPart,
    {
        isPartialUpload: true,
        chunkSize: 262144
    }
);
if (error) {
    throw error;
}
const { error: resumeError, data: metadata } = await storage.uploadStream(
    'large.bin',
    remainder,
    {
        sessionUri: checkpoint.sessionUri,
        offset: checkpoint.nextOffset,
        resumeCRC32C: checkpoint.crc32c
    }
);
if (resumeError) {
    throw resumeError;
}
```
