# FirestoreDataConverter

Converters distinguish application data from stored data. Full writes accept field transforms; merge writes accept nested partial data. A replacement `set()` calls `toFirestore(data)` with one argument, and a merge calls `toFirestore(data, options)`.

```typescript
import type {
    FirestoreDataConverter,
    WithFieldValue,
    PartialWithFieldValue,
    SetOptions,
    QueryDocumentSnapshot
} from 'firebase-admin-edge';

type App = { label: string };
type Stored = { name: string };

class LabelConverter implements FirestoreDataConverter<App, Stored> {
    toFirestore(model: WithFieldValue<App>): WithFieldValue<Stored>;
    toFirestore(
        model: PartialWithFieldValue<App>,
        options: SetOptions
    ): PartialWithFieldValue<Stored>;
    toFirestore(
        model: PartialWithFieldValue<App>
    ): PartialWithFieldValue<Stored> {
        if (model.label === undefined) return {};
        return { name: model.label };
    }
    fromFirestore(snapshot: QueryDocumentSnapshot): App {
        return { label: String(snapshot.get('name')) };
    }
}

const ref = db.doc('users/a').withConverter(new LabelConverter());
const { error: operationError1 } = await ref.set({ label: 'Alice' });
if (operationError1) {
    throw operationError1;
}
const { error: operationError2 } = await ref.set({}, { merge: true });
if (operationError2) {
    throw operationError2;
}
const { error: operationError3 } = await ref.update({ name: 'Alicia' });
if (operationError3) {
    throw operationError3;
} // Updates use Stored, bypassing the converter.
const { error: snapshotsError, data: snapshots } = await db.getAll(ref);
if (snapshotsError) {
    throw snapshotsError;
} // DocumentSnapshot<App, Stored>[]
const partitions = db
    .collectionGroup('users')
    .withConverter(new LabelConverter())
    .getPartitions(1);
for await (const partition of partitions) {
    const query = partition.toQuery(); // Query<App, Stored>
    const { error: summaryError, data: summary } = await query.count().get();
    if (summaryError) {
        throw summaryError;
    }
    console.log(summary.data().count); // number
}
```

Batch, transaction, and BulkWriter object updates likewise use the stored model. Optional nested maps and index signatures support dotted field paths. Runtime Firestore data is still schemaless, so converters should validate stored data when needed.
