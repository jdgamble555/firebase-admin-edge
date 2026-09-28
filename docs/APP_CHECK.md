# AppCheck

[Back to the README](../README.md)

Create custom-provider tokens and verify App Check tokens on edge runtimes. Methods
return `{ error, data }`, using `FirebaseEdgeError` for failures.

## Setup

```ts
import { AppCheck } from 'firebase-admin-edge';

const appCheck = new AppCheck(serviceAccount);
// Or use firebaseServer.appCheck from createFirebaseEdgeServer().
```

Use `new AppCheck(serviceAccount, options?)` to customize initialization.
The exported `AppCheckOptions` type includes `fetch`, `cache`, and `cacheName`.
The fetch implementation defaults to `globalThis.fetch` and the cache prefix to `__cache`:

```ts
import { AppCheck, TokenCache } from 'firebase-admin-edge';

const tokens = new TokenCache();
const appCheck = new AppCheck(serviceAccount, {
    fetch,
    cache: {
        getCache: (key) => tokens.get(key),
        setCache: (key, value, ttlMs) => tokens.set(key, value, ttlMs)
    },
    cacheName: 'my-app'
});
```

OAuth credentials use a service-account-specific cache key and expire a minute early.
Public signing keys are cached by the verifier, with support for key rotation.
Reuse the instance across requests when possible. The Auth emulator setting does
not disable App Check verification or redirect its requests.

## Verify requests

Clients send their Firebase App Check token in `X-Firebase-AppCheck`. This checks
the signature, expiry, issuer, project audience, and required claims. The service
account's `project_id` must match a project audience in the token.

```ts
const token = request.headers.get('X-Firebase-AppCheck') ?? '';
const { error, data } = await appCheck.verifyToken(token);
if (error) {
    return new Response('Invalid App Check token', { status: 401 });
}
if (data.appId !== expectedAppId) {
    return new Response('Unexpected app', { status: 403 });
}
// Continue the protected operation. data.token contains verified claims.
```

Verification is explicit: exposing `firebaseServer.appCheck` does not automatically
enforce it on your routes. App Check identifies an app; continue to use Firebase
Auth and authorization checks for user access.

## Replay protection

For sensitive operations, obtain a limited-use token from the client SDK and consume
it during verification. Grant the backend service account the Firebase App Check
Token Verifier IAM role. Consumption makes an additional authenticated API call.

```ts
const token = request.headers.get('X-Firebase-AppCheck') ?? '';
const { error, data } = await appCheck.verifyToken(token, { consume: true });
if (error || data.alreadyConsumed) {
    return new Response('Invalid or reused App Check token', { status: 401 });
}
// Perform the protected operation only after this check.
```

`alreadyConsumed` is returned only when consumption was requested. A previously
consumed token is reported as `true`; your handler must reject it.

## Custom providers

Only issue a token after your backend has validated the client's custom attestation.
Use a registered Firebase app ID and service account credentials authorized for
the App Check API.

```ts
// Run your custom attestation checks before this call.
const { error, data } = await appCheck.createToken(verifiedAppId, {
    ttlMillis: 60 * 60 * 1000
});
if (error) {
    throw error;
}
// Return this to the Firebase client custom provider.
return Response.json(data); // { token, ttlMillis }
```

The optional TTL must be between 30 minutes and 7 days, inclusive. Omitting it
uses Firebase's default. The backend signs a five-minute assertion and exchanges
it for the returned App Check token; the assertion is never the client token.

For custom-provider tokens that support replay protection, set `limitedUse: true`.
You can also supply a `jti` to choose their replay identity:

```ts
// Run your custom attestation checks before issuing a token.
const { error, data } = await appCheck.createToken(verifiedAppId, {
    ttlMillis: 60 * 60 * 1000,
    limitedUse: true,
    jti: verifiedOperationId
});
if (error) {
    throw error;
}
return Response.json(data);
```

`limitedUse` defaults to `false`. Supplying `jti` requires `limitedUse: true`,
even when `jti` is an empty string. Omit `jti` or use an empty string to let Firebase
generate it. Limited-use tokens with the same `jti` count as the same token for
replay protection; use a distinct identity for each independent operation.
The backend must still call `verifyToken(token, { consume: true })` and reject
`alreadyConsumed` tokens as shown above.

See Firebase's [backend verification guide](https://firebase.google.com/docs/app-check/custom-resource-backend)
and [custom provider guide](https://firebase.google.com/docs/app-check/custom-provider).
