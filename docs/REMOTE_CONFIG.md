# RemoteConfig

Manage Firebase Remote Config client templates and evaluate server templates from
Node.js and edge runtimes. The implementation uses Firebase REST endpoints, your
service account, standard fetch, and Web Crypto. Enable the Remote Config API and
grant the service account permission to read or manage Remote Config as needed.

```ts
import { RemoteConfig } from 'firebase-admin-edge';

const remoteConfig = new RemoteConfig(serviceAccount, {
    fetch: globalThis.fetch,
    cache, // Optional package CacheConfig, used for OAuth access tokens.
    cacheName: '__cache'
});

// Also available as firebaseServer.remoteConfig with the server's fetch/cache.
const { error, data: template } = await remoteConfig.getTemplate();
if (error) {
    throw error;
}

template.parameters.welcome_message = {
    defaultValue: { value: 'Welcome!' },
    valueType: 'STRING'
};
template.version = { description: 'Update welcome message' };

const { error: validationError, data: validated } =
    await remoteConfig.validateTemplate(template);
if (validationError) {
    throw validationError;
}

const { error: publishError, data: published } =
    await remoteConfig.publishTemplate(validated);
if (publishError) {
    throw publishError;
}
console.log(published.etag);
```

Network operations return `{ error, data }`. Errors are `FirebaseEdgeError`
instances, with `remote-config/*` codes for Remote Config failures. OAuth failures
retain the package's existing authentication error codes. Constructors reject
invalid initialization with an exception, following the other service classes.

## Templates and version history

These methods match the official Admin Node.js SDK's Remote Config operations:

| Method                                | Behavior                                                    |
| ------------------------------------- | ----------------------------------------------------------- |
| `getTemplate()`                       | Read the active client template and its ETag.               |
| `getTemplateAtVersion(versionNumber)` | Read an earlier client template.                            |
| `validateTemplate(template)`          | Validate without publishing; retain the input ETag.         |
| `publishTemplate(template, options?)` | Publish with ETag protection; optional `{ force: true }`.   |
| `rollback(versionNumber)`             | Republish a previous client template as the active version. |
| `listVersions(options?)`              | List version metadata and a next-page token.                |
| `createTemplateFromJSON(json)`        | Synchronously parse a client template into a result.        |
| `initServerTemplate(options?)`        | Synchronously construct a stateful server template.         |
| `getServerTemplate(options?)`         | Construct and load a server template, returning a result.   |

```ts
const { error: historyError, data: history } = await remoteConfig.listVersions({
    pageSize: 20,
    startTime: new Date('2025-01-01T00:00:00Z'),
    endTime: '2026-01-01T00:00:00Z',
    endVersionNumber: '100'
});
if (historyError) {
    throw historyError;
}
console.log(history.versions, history.nextPageToken);

const { error: previousError, data: previous } =
    await remoteConfig.getTemplateAtVersion('42');
if (previousError) {
    throw previousError;
}

// toJSON() includes the ETag; JSON.stringify(template) also works.
const json = JSON.stringify(previous.toJSON());
const { error: parseError, data: restored } =
    remoteConfig.createTemplateFromJSON(json);
if (parseError) {
    throw parseError;
}

const { error: forceError } = await remoteConfig.publishTemplate(restored, {
    force: true
});
if (forceError) {
    throw forceError;
}

const { error: rollbackError, data: rolledBack } =
    await remoteConfig.rollback('42');
if (rollbackError) {
    throw rollbackError;
}
console.log(rolledBack.version);
```

Use `history.nextPageToken` as `pageToken` on the next `listVersions()` call.
Version numbers accept numbers or decimal int64 strings; use strings for values
beyond JavaScript's safe integer range. Version timestamps use UTC strings, and
only `version.description` is sent during validation or publication. Client
parameters, groups, conditions, rollout values, personalization values, and
experiment variants are preserved. Experiment exposure percentages must be
between 0 and 100.

Normal publication sends `If-Match` with the template ETag. A conflicting update
returns `remote-config/etag-mismatch`. `{ force: true }` sends `If-Match: *` and can
overwrite concurrent edits. Validation is a separate request and does not publish.

## Server templates

Server templates come from the `firebase-server` namespace. They are separate
from client templates; client template publication does not publish server
templates. Configure server parameters in Firebase Console, or load independently
obtained server template data with `set()`.

```ts
const serverTemplate = remoteConfig.initServerTemplate({
    defaultConfig: { enabled: false, greeting: 'Hello', limit: 10 }
});

const { error: loadError } = await serverTemplate.load();
if (loadError) {
    throw loadError;
}

// Evaluation is asynchronous because percentage conditions use Web Crypto.
const { error: evaluationError, data: config } = await serverTemplate.evaluate({
    randomizationId: 'stable-user-id',
    country: 'US',
    appVersion: '2.3.0',
    accountAge: 30
});
if (evaluationError) {
    throw evaluationError;
}

console.log(config.getBoolean('enabled'));
console.log(config.getString('greeting'));
console.log(config.getNumber('limit'));

const value = config.getValue('greeting');
console.log(value.asString(), value.asBoolean(), value.asNumber());
console.log(value.getSource()); // 'remote', 'default', or 'static'
console.log(config.getAll()); // A new map of all configured Value objects.

const saved = serverTemplate.toJSON();
if (saved) {
    const { error: setError } = serverTemplate.set(JSON.stringify(saved));
    if (setError) {
        throw setError;
    }

    // Synchronous initialization with prefetched data avoids a network request.
    const prefetched = remoteConfig.initServerTemplate({ template: saved });
    console.log(prefetched.toJSON());
}

const { error: serverError, data: loaded } =
    await remoteConfig.getServerTemplate({
        defaultConfig: { enabled: false }
    });
if (serverError) {
    throw serverError;
}
console.log(loaded.toJSON());
```

`load()`, `set()`, and `evaluate()` return results. `set()` accepts a server template
object or JSON string. Invalid updates leave the previous template available.
`toJSON()` returns a snapshot, or `undefined` before a successful load/set.
Evaluation before loading/setting returns `remote-config/failed-precondition`.
Keep a loaded template in your application's lifetime and call `load()` when you
want to refresh it; there is no background polling or automatic refresh.

Conditions follow template priority order. Supported conditions include boolean
AND/OR, constants, seeded percentage comparisons and ranges, and every custom
signal string, regex, numeric, and semantic version operator. Percentage assignment
uses the same SHA-256 bucket calculation as the Admin SDK and requires a stable
`randomizationId`. Custom signals are direct properties of the evaluation context.
Unknown conditions and invalid regexes evaluate to false. Nested boolean evaluation
uses the Admin SDK's depth limit. Semantic versions use up to five numeric segments.

Matched remote values override template defaults, which override `defaultConfig`.
`useInAppDefault` retains application defaults. Missing parameters return static
values: empty string, false, and zero. Boolean conversion recognizes `1`, `true`,
`t`, `yes`, `y`, and `on`, ignoring case. Invalid numeric strings return zero.
Server evaluation does not assign client experiments, rollouts, or personalizations.

## Client fetch responses

```ts
import { RemoteConfigFetchResponse } from 'firebase-admin-edge';

// config is the evaluated ServerConfig from the preceding example.
const response = new RemoteConfigFetchResponse(
    serviceAccount.project_id,
    config,
    request.headers.get('if-none-match') ?? undefined
);
const payload = response.toJSON();
console.log(payload.status, payload.eTag, payload.config);
```

The constructor takes a project ID in place of the Admin SDK's Firebase App.
The response contains status 200 and string values, or status 304 without config
when the request ETag matches. It uses the Admin SDK's fetch ETag calculation.

## Compatibility and references

All nine RemoteConfig service methods and the server-template, server-config,
value, template/version serialization, and fetch-response methods are covered.
Package differences are service-account initialization, `{ error, data }` results,
and asynchronous `ServerTemplate.evaluate()` for portable Web Crypto hashing.
`initServerTemplate()` returns the instance directly, like the SDK; initialization
errors throw. There is no Firebase App registry or `getRemoteConfig(app)` singleton
because this package constructs services directly.

The public data types are adapted from Google's Apache-2.0-licensed
[Firebase Admin Node.js SDK source](https://github.com/firebase/firebase-admin-node/tree/master/src/remote-config),
with its copyright and license notice retained in the type module. Implementation
uses the [official API reference](https://firebase.google.com/docs/reference/admin/node/firebase-admin.remote-config)
and [server configuration documentation](https://firebase.google.com/docs/remote-config/server).
