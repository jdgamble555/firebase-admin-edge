# Timestamp

Firestore timestamps preserve nanoseconds. Reads now return `Timestamp` instead
of `Date`. Convert to a JavaScript date when millisecond precision is sufficient.

```typescript
import { Timestamp } from 'firebase-admin-edge';

const precise = new Timestamp(1700000000, 123456789);
const now = Timestamp.now();
const fromDate = Timestamp.fromDate(new Date());
const fromMillis = Timestamp.fromMillis(1700000000123);
console.log(precise.seconds, precise.nanoseconds);
console.log(precise.toDate(), precise.toMillis(), precise.toJSON());
console.log(precise.isEqual(fromMillis));
console.log(precise.valueOf()); // lexically sortable timestamp string
console.log(precise < now);

await firestore.doc('examples/time').set({ precise, fromDate });
```

Seconds must be an integer in the year 0001–9999 range; nanoseconds must be an
integer from 0 through 999,999,999. Invalid dates and non-finite inputs throw.
The REST encoder uses an RFC3339 representation preserving all nine fractional
digits; `fromString()` and `toString()` support this internal conversion.

`toMillis()` floors sub-millisecond precision, while `toDate()` rounds to the nearest millisecond, matching the server SDK.

```ts
const precise = Timestamp.fromInstant({ epochNanoseconds: -1n });
// Requires native Temporal or a caller-provided global Temporal polyfill.
const instant = precise.toInstant();
console.log(instant.epochNanoseconds);
```

No Temporal package is installed automatically. `toInstant()` reports a failed precondition when the runtime lacks Temporal.
