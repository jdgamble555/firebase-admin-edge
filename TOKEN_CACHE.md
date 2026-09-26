# TokenCache

[Main README](README.md) · [Standalone functions](FUNCTIONS.md)

Keep values in memory until they expire.

```ts
import { TokenCache } from 'firebase-admin-edge';

const cache = new TokenCache();
cache.set('example', 'hello', 60 * 1000); // Keep it for one minute.

const value = cache.get<string>('example'); // 'hello', or undefined after expiry.
```

| Method                    | What it does                                              |
| ------------------------- | --------------------------------------------------------- |
| `set(key, value, ttlMs?)` | Saves a value. The default lifetime is one hour.          |
| `get(key)`                | Reads a value. Returns `undefined` if missing or expired. |
| `has(key)`                | Checks whether an unexpired value exists.                 |
| `delete(key)`             | Removes a value.                                          |

Cache times are in **milliseconds**. Values live only in this cache instance's memory.
These methods return directly; they do not use `{ data, error }`.
