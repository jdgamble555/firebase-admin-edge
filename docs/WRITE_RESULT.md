# WriteResult

Successful document and BulkWriter results contain a runtime `WriteResult` in
`data`; batch commits contain an array of them. Transaction writes are queued
synchronously, and `runTransaction()` returns the callback's value in `data`.

```typescript
import { WriteResult } from 'firebase-admin-edge';

const { error: resultError, data: result } = await db
    .doc('users/a')
    .set({ active: true });
if (resultError) {
    throw resultError;
}
console.log(result instanceof WriteResult, result.writeTime.toDate());
console.log(result.isEqual(result)); // true
```

Equality compares write timestamps. Values from different writes can compare equal when Firestore assigns the same timestamp.
