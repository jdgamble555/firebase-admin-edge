---
'firebase-admin-edge': minor
---

Add Identity, IdentityQuery, and IdentityCountQuery with at most one account-data request per get. Support native sorting and offset queries capped at 500 users, explicit token pagination capped at 1,000, reversed-order limitToLast, and count().get() using server-side count-only requests. Restrict fetching and counting to the same native uid, email, or phoneNumber filter; omit local-only filters and scan-based cursors. Expose the client as server.identity.

Add chainable or(field, operator, value) clauses with == and in for up to 100 mixed exact identifiers in one lookup request. Keep OR and where mutually exclusive, reject unsupported query modifiers, and document that general AND and nested Boolean expressions are unavailable.

Validate equality identifiers and direct query/count options before I/O to prevent malformed filters from silently returning all accounts. Make OR identifier types exclusive. Add read-only live capability tests confirming that additional query expressions are ignored, plus mixed OR and native sorting coverage.

Add exact byUid() and byProvider() lookups plus where('initialEmail', '==', email) with one account-data request, and support initial-email identifiers in admin getUsers().

Make fluent builder types depend on the selected filter and pagination mode, with runtime guards for unsupported combinations in either chaining order.

Add byEmail() and byPhoneNumber() single-user lookups alongside byUid() and byProvider(), with the same typed builder restrictions and single-request behavior.

Support where(field, "in", values) for UID, email, phone number, and initial email through one batch lookup, with at most 100 identifiers and fetch-only builder types.

Add where("provider", "in", pairs) for single-request batch provider-identity lookups, with typed pairs, a 100-identifier cap, and fetch-only chaining.

Add fluent account creation, UID profile updates, single and explicit UID-batch deletion, and imports without automatic record readback.

Add existing-only UID set() for replacement of the documented profile schema, with explicit defaults and no create fallback. Writes through non-UID identifiers remain unavailable.

Use customClaims in Identity import payloads. Omitted nullable profile fields in set() clear automatically using the native endpoint deletion representation.

Support password: null in UID profile updates and creation/sign-in timestamps through user.metadata.update().

Support customClaims and metadata in user.update() alongside profile fields in one write. Keep the dedicated claims and metadata properties. user.set() replaces claims and writable metadata too: omitted/null claims clear to {}, and omitted/null creation/sign-in timestamps reset to 0 (Unix epoch), including omitted fields of partially supplied metadata.

Add claims.get(), metadata.get(), claims.byKey(name).get()/set(value)/update(value)/delete(), and metadata.revokeTokens() on UID references. Field mutations preserve other claims using a read followed by a write; resource reads return user-not-found for missing accounts.

Add optional claims schemas on Identity, users(), and byUid(), carrying typed keys/values through queries, imports, references, and claims operations. Standardize successful single-user Identity writes to data: { uid }, including claims writes, user deletion, and token revocation; preserve batch summaries and adminAuth results.
