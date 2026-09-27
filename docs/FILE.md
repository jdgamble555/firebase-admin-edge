# File

`get({ autoCreate: true })` creates only a missing live object. A generation selected
on the reference or in the request, or a soft-deleted lookup, keeps its not-found
error instead of creating a new live object.

Create a reference with `const file = firebaseServer.storage.bucket().file('documents/report.txt')`.
Reference construction does not make a request. Async operations return `{ error, data }`.

```ts
const { error: saveError } = await file.save('Hello', {
    metadata: { contentType: 'text/plain' },
    preconditionOpts: { ifGenerationMatch: 0 }
});
if (saveError) {
    throw saveError;
}

const { error, data } = await file.download();
if (error) {
    throw error;
}
console.log(new TextDecoder().decode(data));
```

Each async expression below returns a result; check `error` before using `data`.

| Method                       | Usage example                                                                                                           | Successful data                                                |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `exists`                     | `await file.exists()`                                                                                                   | Boolean                                                        |
| `get`                        | `await file.get()`                                                                                                      | This reference, with metadata refreshed                        |
| `getMetadata`                | `await file.getMetadata()`                                                                                              | Object metadata                                                |
| `setMetadata`                | `await file.setMetadata({ metadata: { owner: 'user-id' } })`                                                            | Updated metadata                                               |
| `download`                   | `await file.download({ validation: 'crc32c' })`                                                                         | `Uint8Array`                                                   |
| `save`                       | `await file.save(bytes, { resumable: false })`                                                                          | `undefined`; `file.metadata` updated                           |
| `upload`                     | `await file.upload(new Blob(['Hello']))`                                                                                | Alias for `save`                                               |
| `createResumableUpload`      | `await file.createResumableUpload({ contentType: 'text/plain' })`                                                       | Session URI                                                    |
| `delete`                     | `await file.delete({ ignoreNotFound: true })`                                                                           | `undefined`                                                    |
| `copy`                       | `await file.copy('copy.txt', { metadata: { copied: 'yes' } })`                                                          | Destination File                                               |
| `move`                       | `await file.move('archive/report.txt')`                                                                                 | Destination File                                               |
| `rename`                     | `await file.rename('renamed.txt')`                                                                                      | Alias for `move`                                               |
| `moveFileAtomic`             | `await file.moveFileAtomic('new-name.txt')`                                                                             | Destination File; same bucket required                         |
| `getSignedUrl`               | `await file.getSignedUrl({ action: 'read', version: 'v4', expires: Date.now() + 300000 })`                              | Signed URL                                                     |
| `getDownloadURL`             | `await file.getDownloadURL()`                                                                                           | Firebase token URL                                             |
| `generateSignedPostPolicyV2` | `await file.generateSignedPostPolicyV2({ expires: Date.now() + 300000 })`                                               | Policy string, base64 policy, signature                        |
| `generateSignedPostPolicyV4` | `await file.generateSignedPostPolicyV4({ expires: Date.now() + 300000, contentLengthRange: { min: 1, max: 1048576 } })` | Form URL and fields                                            |
| `isPublic`                   | `await file.isPublic()`                                                                                                 | Anonymous accessibility boolean                                |
| `makePublic`                 | `await file.makePublic()`                                                                                               | Updated ACL entry                                              |
| `makePrivate`                | `await file.makePrivate({ strict: true })`                                                                              | Response metadata                                              |
| `restore`                    | `await file.restore({ generation: '1234567890' })`                                                                      | Restored File                                                  |
| `getExpirationDate`          | `await file.getExpirationDate()`                                                                                        | Retention expiration Date; error when none exists              |
| `setStorageClass`            | `await file.setStorageClass('NEARLINE')`                                                                                | File after server-side rewrite                                 |
| `rotateEncryptionKey`        | `await file.rotateEncryptionKey({ encryptionKey: new Uint8Array(32) })`                                                 | File after rewrite; use a securely generated key in production |
| `request`                    | `await file.request({ method: 'GET', qs: { generation: '123' } })`                                                      | JSON response                                                  |

Copy destinations accept names, `gs://bucket/object` URLs, or another File reference. Copy options use top-level fields such as `contentType` and `storageClass`; `metadata` is the custom key/value map.

Signed URL expiration is an **absolute date**, with V2 the default and V4 limited to seven days. Actions are `read`, `write`, `delete`, and `resumable`. Signed URLs support response headers, extension headers, query parameters and HTTPS custom origins. Firebase download URLs require an existing Firebase download token; the helper does not create one.

```ts
const version = file.bucket.file(file.name, { generation: '1234567890' });
const configured = version.setUserProject('billing-project');
configured.setEncryptionKey(encryptionKeyBytes);
console.log(configured.name, configured.bucket.name, configured.generation);
console.log(configured.cloudStorageURI.toString(), configured.publicUrl());
// setUserProject and setEncryptionKey return the reference synchronously.
```

`createReadStream()` and its `stream()` alias return native `ReadableStream<Uint8Array>`. Errors after creation reject stream reads. `createWriteStream()` returns a native writable stream with a `.result` promise using `{ error, data }`. Closing waits for upload completion.

```ts
const response = new Response(file.createReadStream());
const equivalent = new Response(file.stream({ start: 0, end: 99 }));

const output = file.createWriteStream({
    metadata: { contentType: 'text/plain' }
});
const writer = output.getWriter();
try {
    await writer.write(new TextEncoder().encode('Hello'));
    await writer.close();
} catch {
    // Inspect the package error through output.result below.
}
const { error, data } = await output.result;
if (error) {
    throw error;
}
console.log(data.generation);
```

Uploads accept text, Blob, ArrayBuffer, Uint8Array, and byte streams. Resumable uploads keep bounded buffers and verify CRC32C by default. `resumable: false` buffers stream input and sends a single multipart request when metadata or CRC32C is present. `validation: false` disables automatic checksum verification. `gzip: true` uses CompressionStream. Filesystem paths, Node stream events/callbacks, and disabling Fetch's automatic content decoding are not edge APIs. See [Storage parity](STORAGE_PARITY.md) and [ACL](ACL.md).

## Additional compatible options

MD5 works for buffered and streamed transfers without Node crypto:

```ts
const { error: saveError } = await file.save(bytes, {
    validation: 'md5',
    metadata: { metadata: { revision: 2, reviewed: true } },
    timeout: 30000,
    onUploadProgress: ({ bytesWritten, contentLength }) => {
        console.log(bytesWritten, contentLength);
    }
});
if (saveError) {
    throw saveError;
}
const { error, data } = await file.download({ validation: 'md5' });
if (error) {
    throw error;
}
const streamed = file.stream({ validation: 'md5' });
```

`validation: true` selects CRC32C. MD5 verification needs a server MD5 (composite objects do not have one), the full object, and an unencoded response. A mismatch returns `storage/checksum-mismatch`; a missing usable hash returns `storage/checksum-unavailable`. Stream errors appear while reading, and upload errors remain available through the writable `.result` promise.

| Option                                | Example                                                                                                               |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Requester-pays per operation          | `await file.download({ userProject: 'billing-project' })`                                                             |
| Numeric reference guards              | `await file.getMetadata({ generation: 123, ifMetagenerationMatch: 2 })`                                               |
| Create if missing without overwriting | `await file.get({ autoCreate: true })`                                                                                |
| Last N bytes                          | `await file.download({ end: -100, validation: false })`                                                               |
| Automatic compression by content type | `await file.save(text, { contentType: 'text/plain', gzip: 'auto' })`                                                  |
| Predefined access                     | `await file.save(bytes, { predefinedAcl: 'private' })`                                                                |
| Native writable queue size            | `file.createWriteStream({ highWaterMark: 65536 })`                                                                    |
| Resumable browser origin              | `await file.createResumableUpload({ origin: 'https://example.com' })`                                                 |
| Resume URI alias                      | `await file.save(fullSource, { uri: savedSessionUri })`                                                               |
| Continue a sliced source              | `await file.save(remainingBytes, { uri: savedSessionUri, offset: acknowledgedBytes, resumeCRC32C: precedingCrc32c })` |
| Copy ACL and billing                  | `await file.copy('copy.txt', { predefinedAcl: 'private', userProject: 'billing-project' })`                           |
| Restore original access               | `await file.restore({ generation: '123', copySourceAcl: true })`                                                      |

`offset` means the supplied source starts at that session byte offset. With validation enabled, supply the CRC32C of the preceding bytes as a base64 digest or 32-bit value. The server must already have acknowledged those bytes. For MD5, supply the complete source instead. Upload timeouts apply to individual Fetch requests. `public`/`private` are predefined-ACL aliases and cannot both be true.

Signing still uses the configured private key unless `signingEndpoint` is explicitly supplied:

```ts
const { error, data } = await file.getSignedUrl({
    action: 'read',
    version: 'v4',
    expires: Date.now() + 300000,
    signingEndpoint:
        'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/',
    queryParams: { generation: 123 },
    extensionHeaders: { 'x-goog-meta-tags': ['one', 'two'] }
});
if (error) {
    throw error;
}
```

Only Google IAM Credentials HTTPS endpoints are accepted for authenticated signing. `host` selects an alternate HTTPS API origin; `cname` selects a bucket-bound origin. For browser-selected filenames, `bucket.file('uploads/${filename}').generateSignedPostPolicyV4({ expires })` uses a prefix condition in the policy.

## Partial uploads and custom CRC32C

`isPartialUpload: true` keeps the resumable session open. Supply `chunkSize` and a positive multiple of 256 KiB of input. An optional `size` describes the eventual whole object and must exceed the partial input plus its starting offset. Partial uploads cannot use automatic gzip or whole-object MD5.

```ts
const { error, data: checkpoint } = await file.save(firstPart, {
    isPartialUpload: true,
    chunkSize: 262144
});
if (error) {
    throw error;
}

// Persist the checkpoint securely; the session URI grants upload access.
const { error: resumeError } = await file.save(remainingBytes, {
    uri: checkpoint.sessionUri,
    offset: checkpoint.nextOffset,
    resumeCRC32C: checkpoint.crc32c
});
if (resumeError) {
    throw resumeError;
}
```

A partial `save()` returns `{ complete: false, sessionUri, nextOffset, crc32c? }` in `data`; ordinary `save()` still returns `undefined`. Partial writes do not populate completed object metadata. If a resumed prefix has no supplied checksum and validation is disabled, the checkpoint omits `crc32c` rather than reporting a suffix checksum as a whole-prefix checksum. `onSession` lets you retain the URI even if the input stream fails. Earlier chunks may already be acknowledged when a later chunk fails validation.

```ts
const writable = file.createWriteStream({
    isPartialUpload: true,
    chunkSize: 262144
});
await firstPartStream.pipeTo(writable);
const { error, data: checkpoint } = await writable.result;
if (error) {
    throw error;
}
console.log(checkpoint.nextOffset, checkpoint.crc32c);
```

Supply `crc32cGenerator` to `bucket.file(name, options)` or inherit it from `storage.bucket(name, options)`. The factory must return a fresh validator implementing `update(Uint8Array)`, `toString()` (canonical base64 CRC32C), and `validate(base64)`. It runs for CRC32C uploads and explicitly validated downloads, including Web Streams and resumed prefixes; MD5 and disabled validation do not invoke it (partial uploads still calculate checkpoint CRC32C).

```ts
import type { CRC32CValidatorGenerator, Storage } from 'firebase-admin-edge';

async function saveWithChecksum(
    storage: Storage,
    crc32cGenerator: CRC32CValidatorGenerator,
    bytes: Uint8Array<ArrayBuffer>
) {
    const file = storage
        .bucket()
        .file('custom-checksum.bin', { crc32cGenerator });
    const { error } = await file.save(bytes);
    if (error) {
        throw error;
    }
    return file.download({ validation: 'crc32c' });
}
```

Additional resource options:

```ts
const { error: restoreError } = await file.restore({
    generation: 123,
    projection: 'full',
    ifGenerationMatch: 0
});
const { error: downloadError, data: bytes } = await file.download({
    encryptionKey,
    validation: 'crc32c'
});
const { error: retentionError } = await file.setMetadata(
    {
        retention: { mode: 'Unlocked', retainUntilTime: '2027-01-01T00:00:00Z' }
    },
    { ifMetagenerationMatch: 2, overrideUnlockedRetention: true }
);
```

Object retention depends on bucket configuration. Selecting `mode: 'Locked'` is irreversible. Writable `acl` metadata is also supported where uniform bucket-level access permits it.
