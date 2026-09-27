# Transaction

`firestore.runTransaction()` begins a server transaction, runs your callback, and
commits its queued writes. Its `data` is the callback's return value and its `error`
reports callback, read, or commit failures. Transaction reads also return
`{ error, data }`; check their errors before queuing writes. Return the unwrapped
data from your callback to avoid nesting result objects. Outstanding failed reads
still prevent commits, even when the callback does not await them.

```typescript
const ref = firestore.doc('counters/visits');
const { error: valueError, data: value } = await firestore.runTransaction(
    async (transaction) => {
        const { error: snapshotError, data: snapshot } =
            await transaction.get(ref);
        if (snapshotError) {
            throw snapshotError;
        }
        const next = Number(snapshot.data()?.value ?? 0) + 1;
        transaction.set(ref, { value: next });
        return next;
    },
    { maxAttempts: 5 }
);
if (valueError) {
    throw valueError;
}
```

All reads must precede all writes. References must belong to the same Firestore
instance. The callback receives `get(documentRef)`, `create`, `set`, `update`, and
`delete`; write signatures and preconditions match [WriteBatch](WRITE_BATCH.md).

```typescript
const { error: operationError1 } = await firestore.runTransaction(
    async (transaction) => {
        const account = firestore.doc('accounts/alice');
        const { error: operationError2 } = await transaction.get(account);
        if (operationError2) {
            throw operationError2;
        }
        transaction.create(firestore.doc('events/new-event'), {
            type: 'changed'
        });
        transaction.update(account, { active: true });
        transaction.delete(firestore.doc('pending/alice'));
    }
);
if (operationError1) {
    throw operationError1;
}
```

An `ABORTED` read/commit retries with a new transaction, up to `maxAttempts`
(default 5). Callbacks can therefore run multiple times. Failed attempts are
rolled back; callback and commit errors remain the reported errors if rollback
also fails. Old transaction objects cannot be reused. Read-write transactions
with no writes finish with an empty commit.

## Read-only transactions

```typescript
import { Timestamp } from 'firebase-admin-edge';

const { error: snapshotError, data: snapshot } = await firestore.runTransaction(
    async (transaction) => {
        const { error, data } = await transaction.get(ref);
        if (error) {
            throw error;
        }
        return data;
    },
    { readOnly: true }
);
if (snapshotError) {
    throw snapshotError;
}
const { error: historicalError, data: historical } =
    await firestore.runTransaction(
        async (transaction) => {
            const { error, data } = await transaction.get(ref);
            if (error) {
                throw error;
            }
            return data;
        },
        { readOnly: true, readTime: Timestamp.fromMillis(Date.now() - 30_000) }
    );
if (historicalError) {
    throw historicalError;
}
console.log(snapshot.data(), historical.data());
```

Read-only transactions use a consistent server snapshot without write locks.
They run once, reject all write methods, and release the server transaction with
rollback after successful reads. `readTime` is optional and must meet Firestore's
server-side retention and precision requirements. `maxAttempts` applies only to
read-write transactions.

## Bulk, query and aggregate reads

```typescript
const { error: operationError1 } = await firestore.runTransaction(
    async (transaction) => {
        const alice = firestore.doc('users/alice');
        const bob = firestore.doc('users/bob');
        const { error: usersError, data: users } = await transaction.getAll(
            alice,
            bob,
            { fieldMask: ['name'] }
        );
        if (usersError) {
            throw usersError;
        }
        const { error: activeError, data: active } = await transaction.get(
            firestore.collection('users').where('active', '==', true)
        );
        if (activeError) {
            throw activeError;
        }
        const { error: totalError, data: total } = await transaction.get(
            firestore.collection('users').count()
        );
        if (totalError) {
            throw totalError;
        }
        transaction.update(
            alice,
            'activeCount',
            total.data().count,
            'seen',
            true
        );
        console.log(users.length, active.size);
    }
);
if (operationError1) {
    throw operationError1;
}
```

All reads use the same server transaction ID. `getAll()` preserves input order,
duplicates, converters and missing documents. Queries and aggregates retain their
constraints. Pending reads settle before commit, including reads the callback
did not explicitly await. Reads after a queued write are rejected.

Custom transaction timeouts are not implemented. Methods prefixed `_` are internal
lifecycle hooks.

```typescript
const { error: resultError, data: result } = await db.runTransaction(
    async (transaction) => {
        const { error, data } = await transaction.execute(
            db.pipeline().collection('books').limit(5)
        );
        if (error) {
            throw error;
        }
        return data;
    }
);
if (resultError) {
    throw resultError;
}
console.log(result.results.map((row) => row.data()));
```

Pipeline reads must precede queued writes and use the transaction's Firestore instance.

Mutation pipelines also commit when no document writes were queued. After a
mutation pipeline, further reads are rejected; document writes can still be queued
before the transaction commits. Read-only transactions reject mutation pipelines.

`get()`, `getAll()`, and aggregate reads retain both application and stored model types. Object updates are checked against the stored model. Replacement `set()` invokes the one-argument converter overload; merge writes pass their original options. See [converter examples](FIRESTORE_DATA_CONVERTER.md).
