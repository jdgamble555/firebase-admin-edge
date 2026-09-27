import { expect, it, vi } from 'vitest';
import { Notification } from './storage-notification.js';
import type { Storage } from './storage.js';
import type { Bucket } from './storage-bucket.js';
import { FirebaseEdgeError } from '../auth/errors.js';
it('caches metadata, returns references, and handles missing and forbidden resources', async () => {
    const metadata = {
        id: '1',
        topic: '//pubsub.googleapis.com/projects/p/topics/t'
    };
    const transport = {
        getNotification: vi
            .fn()
            .mockResolvedValue({ error: null, data: metadata }),
        deleteNotification: vi.fn()
    };
    const notification = new Notification(
        {} as Bucket,
        '1',
        transport as unknown as Storage
    );
    await expect(notification.getMetadata()).resolves.toEqual({
        error: null,
        data: metadata
    });
    await expect(notification.get()).resolves.toEqual({
        error: null,
        data: notification
    });
    await expect(notification.exists()).resolves.toEqual({
        error: null,
        data: true
    });
    expect(notification.metadata).toBe(metadata);
    await notification.delete();
    expect(transport.deleteNotification).toHaveBeenCalledWith('1');
    transport.getNotification.mockResolvedValue({
        error: new FirebaseEdgeError({
            code: 'storage/resource-not-found',
            message: 'missing'
        }),
        data: null
    });
    await expect(notification.exists()).resolves.toEqual({
        error: null,
        data: false
    });
    const denied = new FirebaseEdgeError({
        code: 'storage/permission-denied',
        message: 'denied'
    });
    transport.getNotification.mockResolvedValue({ error: denied, data: null });
    await expect(notification.exists()).resolves.toEqual({
        error: denied,
        data: null
    });
    await expect(notification.get()).resolves.toEqual({
        error: denied,
        data: null
    });
});
