# FieldPath

Use segments to distinguish a literal field name containing dots from nested
fields. The encoder quotes and escapes segments for Firestore REST requests.

```typescript
import { FieldPath } from 'firebase-admin-edge';

const nested = new FieldPath('profile', 'name');
const literal = new FieldPath('profile.name');
console.log(nested.toString()); // profile.name
console.log(literal.toString()); // `profile.name`
console.log(nested.isEqual(literal)); // false

await firestore.collection('users').where(literal, '==', 'Alice').get();
await firestore.collection('users').orderBy(nested).select(nested).get();
await firestore
    .collection('users')
    .where(FieldPath.documentId(), 'in', ['alice', 'bob'])
    .get();
await firestore
    .doc('users/alice')
    .set({ 'profile.name': 'Alice' }, { mergeFields: [literal] });
```

At least one non-empty segment is required. Document-ID filters accept IDs or
`DocumentReference` values; document-ID cursors accept the same values when
ordered by `FieldPath.documentId()`. Object-form updates use dotted string keys;
variadic `update(fieldPath, value, ...)` is not implemented.
