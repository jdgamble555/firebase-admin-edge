import { expect, it, vi } from 'vitest';
import { reportStorageProgress } from './storage-progress.js';

it('allows absent observers and awaits asynchronous observers', async () => {
    const progress = { bytesTransferred: 3, totalBytes: 3, complete: true };
    await reportStorageProgress(undefined, progress);
    const callback = vi.fn(async () => undefined);
    await reportStorageProgress(callback, progress);
    expect(callback).toHaveBeenCalledWith(progress);
});
it('reports observer failure after acknowledged upload progress', async () => {
    await expect(
        reportStorageProgress(
            () => {
                throw new Error('observer');
            },
            { bytesTransferred: 3, complete: true }
        )
    ).rejects.toMatchObject({
        code: 'storage/progress-callback-failed',
        cause: { message: 'observer' }
    });
});
