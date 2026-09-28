---
'firebase-admin-edge': major
---

Replace IdentityReference's positional boolean arguments with an optional typed
options object. Use `new IdentityReference(auth, identifier)` for a single read-only
lookup, `{ uidReference: true }` to enable UID mutations, or `{ multiple: true }`
to return an array of matches. Export IdentityReferenceOptions for reusable options.
