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

## Constructor

The class is defined in [errors.ts](../src/auth/errors.ts). It is not exported from
the package's main entry point; consumers can inspect returned errors without
importing the class.

Its constructor accepts `{ message, code? }` and an optional
`{ cause, context }` object. `cause` is an `Error`; `context` holds JSON-compatible
details. Error-code definitions live in
[auth-error-codes.ts](../src/auth/auth-error-codes.ts) and
[firebase-edge-errors.ts](../src/firebase-edge-errors.ts).
