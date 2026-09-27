# Channel

Legacy object-change notification channels are available through `bucket.createChannel(id, config)`. Prefer Pub/Sub notifications for new integrations.

```ts
const { error: createError, data: channel } = await firebaseServer.storage
    .bucket()
    .createChannel('channel-id', {
        address: 'https://example.com/storage-events'
    });
if (createError) {
    throw createError;
}
console.log(channel.id, channel.resourceId);

const { error } = await channel.stop();
if (error) {
    throw error;
}
```

`stop()` returns `{ error, data }` and stops the identified channel/resource pair. Webhook verification and service availability are enforced by Google.
