# Bytes

`Bytes` is an edge-compatible byte wrapper without a Node `Buffer` dependency.
Stored byte fields now decode to `Bytes` instances.

```typescript
import { Bytes } from 'firebase-admin-edge';

const bytes = Bytes.fromUint8Array(new Uint8Array([0, 255]));
const same = Bytes.fromBase64String('AP8=');
console.log(bytes.isEqual(same)); // true
console.log(bytes.toBase64(), bytes.toUint8Array(), bytes.toString());
await firestore.doc('examples/bytes').set({ payload: bytes });
```

Byte arrays are copied on input and output. Invalid base64 and non-byte-array
inputs throw. `Bytes` is provided as an edge-friendly convenience; Admin Node
applications commonly use `Buffer` instead.

Buffer inputs (including subarrays) are also copied. Changing the original Buffer
or the array returned by `toUint8Array()` does not change the stored bytes.
