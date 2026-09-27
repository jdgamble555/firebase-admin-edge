# QueryPartition

Obtain partitions from `CollectionGroup.getPartitions()`. `toQuery()` returns a
query with an inclusive start and exclusive end; an omitted boundary is unbounded.

```typescript
import { FieldPath } from 'firebase-admin-edge';

const group = firestore.collectionGroup('posts');
for await (const partition of group.getPartitions(4)) {
    const { error: snapshotError, data: snapshot } = await partition
        .toQuery()
        .get();
    if (snapshotError) {
        throw snapshotError;
    }
    console.log(snapshot.size);

    // Equivalent explicit construction using the exposed cursor values:
    let query = group.orderBy(FieldPath.documentId());
    if (partition.startAt) query = query.startAt(...partition.startAt);
    if (partition.endBefore) query = query.endBefore(...partition.endBefore);
}
```

The first partition has no `startAt`, and the last has no `endBefore`. Each defined
cursor is an array containing a document reference. Cursor getters return fresh
arrays. Apply these cursors only to the matching collection group ordered by ID.
