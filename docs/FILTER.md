# Filter

```typescript
import { Filter, FieldPath } from 'firebase-admin-edge';

const filter = Filter.and(
    Filter.where('active', '==', true),
    Filter.or(
        Filter.where('role', '==', 'admin'),
        Filter.where(new FieldPath('profile', 'age'), '>=', 18)
    )
);
const results = await firestore.collection('users').where(filter).get();
```

`Filter.where()` accepts the same operators and values as `Query.where()`.
`Filter.and()` and `Filter.or()` require at least one `Filter`. Chaining another
`where()` combines it with the existing query using AND. Invalid operators,
undefined values, and invalid membership arrays throw; Firestore checks index
requirements and restrictions on combinations of operators.
