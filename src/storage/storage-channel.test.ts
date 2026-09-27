import { expect, it, vi } from 'vitest';
import { Channel } from './storage-channel.js';
import type { Storage } from './storage.js';
it('stops its own channel and resource', async () => {
    const referenceAction = vi
        .fn()
        .mockResolvedValue({ error: null, data: {} });
    const channel = new Channel('id', 'resource', {
        referenceAction
    } as unknown as Storage);
    await expect(channel.stop()).resolves.toEqual({ error: null, data: {} });
    expect(referenceAction).toHaveBeenCalledWith(
        { kind: 'channel', id: 'id' },
        { kind: 'stopChannel', id: 'id', resourceId: 'resource' }
    );
});
