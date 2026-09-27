# BulkWriterError

`BulkWriterError` extends `Error` and describes a failed operation. `code` is a
numeric gRPC status; `documentRef`, `operationType`, and `failedAttempts` identify
the operation and number of failed attempts.

```typescript
import { BulkWriterError } from 'firebase-admin-edge';

const writer = firestore.bulkWriter();
try {
    const { error: operationError1 } = await writer.create(
        firestore.doc('users/alice'),
        { name: 'Alice' }
    );
    if (operationError1) {
        throw operationError1;
    }
} catch (error) {
    if (error instanceof BulkWriterError) {
        console.log(error.code, error.message, error.documentRef.path);
        console.log(error.operationType, error.failedAttempts);
    }
} finally {
    const { error: operationError2 } = await writer.close();
    if (operationError2) {
        throw operationError2;
    }
}
```

The writer creates these errors automatically; unknown or transport failures use
status 2. They are also passed to `onWriteError()` before a retry decision.
