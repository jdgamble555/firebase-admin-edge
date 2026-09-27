# Notification

`const notification = firebaseServer.storage.bucket().notification('1')` constructs a reference without a request. Creation and listing use `bucket.createNotification()` and `bucket.getNotifications()`.

Every async operation returns `{ error, data }`:

| Method        | Usage                              | Data                                   |
| ------------- | ---------------------------------- | -------------------------------------- |
| `exists`      | `await notification.exists()`      | Boolean                                |
| `get`         | `await notification.get()`         | This reference with refreshed metadata |
| `getMetadata` | `await notification.getMetadata()` | Configuration                          |
| `delete`      | `await notification.delete()`      | `undefined`                            |

```ts
const { error, data } = await notification.getMetadata();
if (error) {
    throw error;
}
console.log(notification.id, notification.bucket.name, data.topic);
```

The Pub/Sub topic and publisher permissions must exist. This API manages notification configurations; it does not create Pub/Sub topics.

`await bucket.createNotification('topic-id')` resolves the topic in the configured service-account project. `projects/another-project/topics/topic-id` and fully qualified Pub/Sub resource names are also accepted.
