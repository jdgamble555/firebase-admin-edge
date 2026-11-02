# Profiles

`Profiles` manages unique, case-insensitive usernames in Firestore. The server
exposes it as `server.profiles` and shares its configured Firestore instance.

## Configuration

Pass `usernamesCollection` and `usersCollection` to `createFirebaseEdgeServer`:

```ts
const server = createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig,
    cookies,
    redirectUri: 'https://example.com/auth/callback',
    usernamesCollection: 'apps/main/usernames',
    usersCollection: 'apps/main/users',
    profilePhotosPath: 'apps/main/profile-photos',
    profilePhotoMaxBytes: 8 * 1024 * 1024
});
```

The default paths are `usernames` and `users`, respectively. Use different paths
for these collections to keep profiles separate from reservations.
Both top-level collections and fixed
subcollection paths are supported. All users sharing a path share a username
namespace. Use separate paths for separate tenant namespaces.

You can also construct the class with an existing Firestore instance:

```ts
import { Profiles } from 'firebase-admin-edge';

const profiles = new Profiles(
    server.firestore,
    server.adminAuth,
    'usernames',
    'users'
);
```

## Check availability

```ts
const { error, data: available } = await server.profiles.checkUsername('Alice');
if (error) throw error;
console.log(available); // true if unclaimed
```

Names must contain 3–30 ASCII letters, numbers, or underscores. Names are stored
in lowercase; whitespace is rejected. Invalid names return
`profiles/invalid-username`. Availability is advisory; another request can claim
the name before the update.

## Assign or change a username

```ts
const { error: sessionError, data: user } = await server.getUser();
if (sessionError) throw sessionError;
if (!user) throw new Error('Sign in first.');

const { error, data } = await server.profiles.updateUsername(user.uid, 'Alice');
if (error) throw error;
console.log(data); // { uid: user.uid, username: 'alice' }
```

`updateUsername(uid, username)` is an admin operation. Authenticate and authorize
the caller before supplying a UID. The UID must exist in Firebase Auth.
After the Firestore transaction commits, it sets the Auth custom claim
`username` to the normalized name, preserving the user's existing custom claims.
It does not change Firebase Auth's display name.
A Firestore transaction reserves the new name and releases
the previous one. The same transaction sets the lowercase `username` field in
`<usersCollection>/<encoded UID>`, creating the user document if missing and
preserving its other fields. Ordinary Firebase UIDs are used unchanged; characters
requiring URL encoding (such as `/`) are encoded with `encodeURIComponent`.
Reassigning the same name also synchronizes the user document. Another owner's
name returns `profiles/username-taken`. Firestore failures use the usual
`{ error, data }` result convention.

Auth claims are updated separately from the Firestore transaction. If the claim
write fails, the Firestore changes remain committed and the method returns an
error. Retry with the same username to synchronize the claim. Existing tokens
and session cookies retain their old claims until refreshed or reissued.
Avoid concurrent username or custom-claim updates for the same user: Firebase
Auth replaces the complete claims object and cannot commit atomically with Firestore.

The configured collection is reserved for this class: username documents contain
`{ uid }`, and `uid:<encoded UID>` documents contain `{ username }` for reverse
lookup. Keep these records server-managed so clients cannot bypass uniqueness.
Changing the configured path does not migrate existing reservations.

## Update or remove a profile photo

These admin operations require an authorized caller and an existing Firebase Auth
user. They use the configured `usersCollection` (default: `users`) and preserve
other document fields.

```ts
const { error, data } = await server.profiles.updatePhoto(
    user.uid,
    'https://example.com/photos/alice.jpg'
);
if (error) throw error;
console.log(data); // { uid: user.uid, photoURL: 'https://example.com/photos/alice.jpg' }
```

```ts
const { error, data } = await server.profiles.removePhoto(user.uid);
if (error) throw error;
console.log(data); // { uid: user.uid, photoURL: null }
```

`updatePhoto` requires a non-empty valid URL. Both methods update Firebase Auth
first, then merge `photoURL` into the Firestore user document, creating it if
missing. `removePhoto` clears the Auth photo and sets Firestore's `photoURL` to
`null`, then deletes the old managed image from Storage. Photo updates also
delete old managed images by default, after both profile writes succeed.
These writes cannot share
an atomic transaction across Auth and Firestore. If the Firestore write fails,
the method returns an error and Auth remains updated. Retry the same operation to
synchronize both. Existing tokens and sessions need refreshing or reissuing to
reflect the updated Auth photo.

To retain the old stored image when replacing a photo, pass `keepOldPhoto`:

```ts
const { error } = await server.profiles.updatePhoto(
    user.uid,
    'https://example.com/photos/new.jpg',
    { keepOldPhoto: true }
);
if (error) throw error;
```

The same option applies to `updateProfile`:

```ts
const { error } = await server.profiles.updateProfile(
    user.uid,
    { displayName: 'Alice', photoURL: 'https://example.com/photos/new.jpg' },
    { keepOldPhoto: true }
);
if (error) throw error;
```

Cleanup considers old URLs from both Auth and the configured Firestore user doc.
It deletes only objects in the configured Storage bucket under
`<profilePhotosPath>/<encoded UID>/`. Firebase download URLs, Google Storage
download URLs, and bucket-hosted Storage URLs are supported. External photos,
other buckets, and objects outside that user's photo directory are left intact.
Standalone Profiles instances need Storage configured for deletion.
Different URLs pointing to the same object do not trigger deletion. Already
missing objects are ignored, and deletes use generation preconditions.

Storage cleanup occurs after the Auth and Firestore writes. If cleanup fails,
the profile stays updated and the method returns `profiles/photo-cleanup-failed`
with the remaining object path in `error.context.path`. Retry deletion of that
object through Storage; repeating the profile update cannot recover a URL that
has already been replaced. Avoid concurrent photo updates for the same user,
since Auth, Firestore, and Storage cannot participate in one transaction.

## Create a photo upload URL

Set `firebaseConfig.storageBucket` in the main server config. `Profiles` shares
`server.storage` and uses that bucket. The optional main config field
`profilePhotosPath` defaults to `profile-photos`. Upload paths are
`<profilePhotosPath>/<encoded UID>/<unique ID>`. Nested prefixes such as
`apps/main/profile-photos` are supported; use paths without leading or trailing
slashes, empty segments, or dot segments. Changing the prefix does not move
existing photos.

For standalone construction, pass Storage
as the fifth argument after the collection paths:

```ts
const profiles = new Profiles(
    server.firestore,
    server.adminAuth,
    'usernames',
    'users',
    server.storage,
    'profile-photos'
);
```

After authenticating and authorizing the caller, create a URL for their UID:

```ts
const { error, data } = await server.profiles.createPhotoUploadUrl(user.uid, {
    contentType: 'image/png',
    expiresInSeconds: 900
});
if (error) throw error;

const response = await fetch(data.uploadUrl, {
    method: 'PUT',
    headers: data.headers,
    body: photoFile
});
if (!response.ok) throw new Error('Photo upload failed.');
console.log(data.path); // profile-photos/<encoded UID>/<unique ID>
```

Options are optional: the defaults are `image/jpeg` and 900 seconds. Supported
content types are JPEG, PNG, WebP, GIF, and AVIF. The underlying Storage signer
validates expiration (1–604800 seconds) and bucket configuration. The uploader
must send the exact returned Content-Type. Browser uploads need bucket CORS
configured to allow the app's origin, PUT, and Content-Type.

Each call creates a unique object path. The URL grants permission to upload to
that object until expiration; it is not a permanent photo download URL. This
method does not write Auth or Firestore. After a successful upload, obtain a
photo URL accessible to your app's viewers and pass it to `updatePhoto`.
A content-type header does not validate the uploaded image's contents.

### Upload size limit

`profilePhotoMaxBytes` is optional in the main config. Omit it for the default
8 MiB (8,388,608 bytes), supply a positive safe integer for a custom byte limit,
or set it to `null` for no application-imposed size limit:

```ts
const server = createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig,
    cookies,
    redirectUri: 'https://example.com/auth/callback',
    profilePhotoMaxBytes: null
});
```

For standalone `Profiles`, pass the byte limit (or `null`) as the seventh
constructor argument, after `profilePhotosPath`.

The upload result includes `maxBytes` and `headers`. Always send `data.headers`
with the PUT request. Limited uploads sign `x-goog-content-length-range` so Cloud
Storage rejects oversized uploads; omitting or changing that header invalidates
the signature. Include that header in your bucket's allowed CORS headers as well.
With `null`, the size-range header is omitted. Cloud Storage's service limits
still apply. You can also compare `photoFile.size` to `data.maxBytes` before
uploading to show an immediate error to the user.

## Update a display name or profile

`updateDisplayName` updates the user's name in Firebase Auth and the configured
Firestore `usersCollection` (default: `users`):

```ts
const { error, data } = await server.profiles.updateDisplayName(
    user.uid,
    'Alice Smith'
);
if (error) throw error;
console.log(data); // { uid: user.uid, displayName: 'Alice Smith' }
```

`updateProfile` accepts either or both of `displayName` and `photoURL`. It updates
Auth once, then merges the same fields into the Firestore user document:

```ts
const { error, data } = await server.profiles.updateProfile(user.uid, {
    displayName: 'Alice Smith',
    photoURL: 'https://example.com/photos/alice.jpg'
});
if (error) throw error;
console.log(data); // { uid, displayName, photoURL }
```

Omitted or undefined fields are unchanged. Supply `null` to clear either field
in Auth and store `null` in Firestore. An empty display name is allowed; an empty
photo URL is rejected (use `null` instead). At least one field must be supplied,
and fields other than `displayName` and `photoURL` are rejected.

These are admin operations: authenticate and authorize the caller before passing
a UID. Other Firestore fields are preserved, and missing user documents are
created. As with photo updates, Auth and Firestore writes are separate; if the
Firestore write fails after Auth succeeds, the method returns an error. Retry the
same update to synchronize both. Existing tokens and sessions need refreshing or
reissuing to reflect changes.

## Create a resumable photo upload URL

`createResumablePhotoUploadUrl(uid, options)` calls the shared Storage instance's
`createResumableUpload` method and returns a session URI as `uploadUrl`. It uses
the same bucket, `profilePhotosPath`, supported image types, and
`profilePhotoMaxBytes` configuration as signed photo uploads.

```ts
const { error, data } = await server.profiles.createResumablePhotoUploadUrl(
    user.uid,
    {
        size: photoFile.size,
        contentType: 'image/png',
        origin: requestUrl.origin
    }
);
if (error) throw error;

// The browser can upload in one request or use the resumable chunk protocol.
const response = await fetch(data.uploadUrl, {
    method: 'PUT',
    headers: {
        'Content-Type': data.contentType,
        'Content-Range': `bytes 0-${data.size - 1}/${data.size}`
    },
    body: photoFile
});
if (!response.ok) throw new Error('Photo upload failed.');
```

`size` is required and must be a positive safe integer. The method rejects a
size above the configured cap before creating the session; `null` disables that
cap. It forwards the declared size to Storage as the session's expected upload
length. Unlike the signed PUT method, it does not use a signed size-range header.
The optional `origin` is forwarded to Storage for browser CORS; it is not inferred
from the app URL. Content type defaults to `image/jpeg`.

The result contains `{ uploadUrl, path, contentType, size, maxBytes }`.
The session URI authorizes uploads: give it only to the authorized caller.
There is no `expiresInSeconds` option for this method; Storage controls session
lifetime. For interrupted uploads, use the resumable protocol or the existing
`storage.getUploadStatus` and `storage.uploadChunk` methods, resuming from the
confirmed offset. Non-final chunks must be multiples of 256 KiB.

Creating a session does not change Auth or Firestore. After upload completion,
obtain a photo URL accessible to your viewers and call `updatePhoto` or
`updateProfile` to publish it.

## Read a profile

```ts
const { error, data: profile } = await server.profiles.getProfile(user.uid);
if (error) throw error;
console.log(profile); // Stored Firestore document fields, or null when missing.
```

`getProfile` reads the configured `usersCollection` using the same UID encoding as
profile writes. By default, it makes only the Firestore read and does not require
a matching Auth user.

Opt in to an additional Auth lookup when you need its current profile fields:

```ts
const { error, data: profile } = await server.profiles.getProfile(user.uid, {
    includeAuth: true
});
if (error) throw error;
console.log(profile); // Firestore fields plus Auth uid, displayName, and photoURL.
```

Auth's `uid`, `displayName`, and `photoURL` override matching Firestore fields.
Cleared Auth names and photos become `null`. Other Firestore fields, such as
`username`, are preserved. The Auth lookup does not add email, provider records,
custom claims, or internal Auth fields. It does not remove fields already stored
in the Firestore document. A missing Firestore document returns an Auth-based
profile when `includeAuth` is true. Auth errors or a missing Auth user return an
error instead of partial data. The two reads are separate snapshots and do not
write or synchronize either service.

## Complete a photo upload

After either upload flow finishes, pass its returned object path:

```ts
const { error, data } = await server.profiles.completePhotoUpload(
    user.uid,
    upload.path
);
if (error) throw error;
console.log(data); // { uid: user.uid, photoURL: '<Firebase download URL>' }
```

Completion requires a path under the user's configured photo directory in the
configured Storage bucket. It checks stored size against `profilePhotoMaxBytes`
(`null` disables the cap), validates the supported content type, and reads a small,
generation-pinned byte range to check the image signature. This is a signature
check, not full image decoding or malware scanning. Invalid uploads remain stored
but are not published to the profile.

The method preserves custom object metadata, creates or reuses a Firebase download
token with generation preconditions, and obtains the Firebase download URL through
Storage's existing API. Anyone possessing that token URL can download the image.
It then calls `updatePhoto`, updating Auth and Firestore and deleting old managed
photos by default. Missing uploads, validation failures, Storage failures, and
profile update failures return `{ error, data }`. Token creation and profile
updates are separate operations; failures can leave an uploaded object with a
download token before its URL is published. The existing photo cleanup behavior
and cross-service limitations apply.

## Remove a username

```ts
const { error, data } = await server.profiles.removeUsername(user.uid);
if (error) throw error;
console.log(data); // { uid: user.uid, username: null }
```

Removal transactionally releases reservations owned by this UID, deletes its
reverse lookup record, and merges `username: null` into the configured user doc.
Other profile fields remain unchanged. The released name becomes available to
other users immediately. Reservations owned by someone else are never deleted.
Repeated removal succeeds even if no username is assigned.

After the transaction commits, the method removes the `username` custom claim
while preserving other claims. Auth must contain the UID. Claim errors are
returned after the Firestore commit; retry the operation to synchronize Auth.
Existing tokens and session cookies need refreshing or reissuing. Avoid concurrent
username or custom-claim changes for the same user, as with `updateUsername`.

All three methods are server-side APIs. Authorize the caller's access to the UID
before exposing profile reads or mutations in your routes.
