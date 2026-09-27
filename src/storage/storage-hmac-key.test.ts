import { expect, it, vi } from 'vitest';
import { HmacKey } from './storage-hmac-key.js';
import type { Storage } from './storage.js';
import { FirebaseEdgeError } from '../auth/errors.js';
it('manages metadata, state, deletion, and existence without throwing async errors', async () => {
    const metadata = { accessId: 'id', state: 'ACTIVE' };
    const transport = {
        getHmacKey: vi.fn().mockResolvedValue({ error: null, data: metadata }),
        updateHmacKey: vi.fn().mockResolvedValue({
            error: null,
            data: { ...metadata, state: 'INACTIVE' }
        }),
        deleteHmacKey: vi.fn()
    };
    const key = new HmacKey('id', transport as unknown as Storage);
    await expect(key.getMetadata()).resolves.toEqual({
        error: null,
        data: metadata
    });
    await expect(key.get()).resolves.toEqual({ error: null, data: key });
    await expect(key.exists()).resolves.toEqual({ error: null, data: true });
    await key.setMetadata({ state: 'INACTIVE', etag: 'tag' });
    expect(transport.updateHmacKey).toHaveBeenCalledWith(
        'id',
        'INACTIVE',
        'tag'
    );
    expect(key.metadata?.state).toBe('INACTIVE');
    await key.delete();
    expect(transport.deleteHmacKey).toHaveBeenCalledWith('id');
    transport.getHmacKey.mockResolvedValue({
        error: new FirebaseEdgeError({
            code: 'storage/resource-not-found',
            message: 'missing'
        }),
        data: null
    });
    await expect(key.exists()).resolves.toEqual({ error: null, data: false });
    const denied = new FirebaseEdgeError({
        code: 'storage/permission-denied',
        message: 'denied'
    });
    transport.getHmacKey.mockResolvedValue({ error: denied, data: null });
    await expect(key.exists()).resolves.toEqual({ error: denied, data: null });
    await expect(key.get()).resolves.toEqual({ error: denied, data: null });
});
