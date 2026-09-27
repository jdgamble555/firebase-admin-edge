# CollectionGroup

`firestore.collectionGroup(id)` returns a `CollectionGroup`, which extends
[Query](QUERY.md). Its collection ID must be one non-empty path segment.

```typescript
const posts = firestore.collectionGroup('posts');
const { error: publishedError, data: published } = await posts
    .where('published', '==', true)
    .get();
if (publishedError) {
    throw publishedError;
}

const titles = posts.withConverter({
    toFirestore: (title: string) => ({ title }),
    fromFirestore: (snapshot) => String(snapshot.get('title'))
});
const raw = titles.withConverter(null);
```

`withConverter()` preserves the collection-group type. Query constraints such as
`where()` return ordinary queries. Partition the unconstrained collection group
using a positive integer:

```typescript
for await (const partition of titles.getPartitions(10)) {
    const { error: resultsError, data: results } = await partition
        .toQuery()
        .get();
    if (resultsError) {
        throw resultsError;
    }
    console.log(results.docs.map((doc) => doc.data()));
}
```

The server can return fewer partitions than requested. A request for one partition
does not call the partition endpoint. All server pages are combined, sorted and
deduplicated before creating adjacent ranges. Each partition preserves the
converter and orders documents by document ID. See [QueryPartition](QUERY_PARTITION.md).

Collection groups and their partitions retain both converter model types. See [the converter and partition example](FIRESTORE_DATA_CONVERTER.md).
