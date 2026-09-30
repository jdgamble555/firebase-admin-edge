# FirebaseEdgeError

[Main README](../README.md) · [Standalone functions](FUNCTIONS.md)

`FirebaseEdgeError` extends JavaScript's `Error` class. Auth methods return it
in the `error` field when an operation fails.

## Handle a returned error

```ts
const { data: user, error } =
    await firebaseServer.adminAuth.getUser('user-uid');

if (error) {
    console.error(error.code, error.message);
    throw error;
}

console.log(user);
```

| Property  | Meaning                                                               |
| --------- | --------------------------------------------------------------------- |
| `name`    | `FirebaseEdgeError`.                                                  |
| `message` | Description of the failure.                                           |
| `code`    | Optional package error code, such as `auth/admin-user-lookup-failed`. |
| `cause`   | Optional underlying error, including a mapped Firebase API error.     |
| `context` | Optional details attached to the error.                               |
| `stack`   | Standard JavaScript error stack.                                      |

Some operations wrap the underlying error in `cause`; others return it directly.
Check the returned `code` and inspect `cause` when you need more detail.

## Provider credential exchange failures

Firebase's `INVALID_IDP_RESPONSE` maps to
`auth/endpoint-provider-authentication-failed`, with the message
“Authentication with the provider failed during credential exchange.”
`INVALID_PROVIDER_ID` maps to `auth/endpoint-invalid-provider-id`.

The provider authentication error's `context` retains the HTTP status as
`firebaseCode` and the fixed `firebaseErrorCode: 'INVALID_IDP_RESPONSE'` label.
When recognized, it also includes `oauthError: 'invalid_client'` and
`diagnostic: 'invalid-client-secret'`. Raw provider responses and nested error
details are omitted, so OAuth codes, tokens, and secrets are not copied into
the mapped error, including its cause and context.

An invalid client secret still requires correcting the OAuth client secret in
Firebase configuration. This mapping improves the diagnosis; it does not repair
the configuration.

## Constructor

The class is defined in [errors.ts](../src/auth/errors.ts). It is not exported from
the package's main entry point; consumers can inspect returned errors without
importing the class.

Its constructor accepts `{ message, code? }` and an optional
`{ cause, context }` object. `cause` is an `Error`; `context` holds JSON-compatible
details. Error-code definitions live in
[auth-error-codes.ts](../src/auth/auth-error-codes.ts) and
[firebase-edge-errors.ts](../src/firebase-edge-errors.ts).
