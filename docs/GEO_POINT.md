# GeoPoint

```typescript
import { GeoPoint } from 'firebase-admin-edge';

const location = new GeoPoint(41.88, -87.63);
console.log(location.latitude, location.longitude, location.toJSON());
console.log(location.isEqual(new GeoPoint(41.88, -87.63))); // true
await firestore.doc('cities/chicago').set({ location });
```

Reads return `GeoPoint` instances. Coordinates must be finite numbers: latitude
within -90 to 90 and longitude within -180 to 180. Values can be used in document
writes and query comparisons; geospatial distance queries are not implemented.
