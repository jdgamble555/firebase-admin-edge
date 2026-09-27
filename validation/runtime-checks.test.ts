import { expect, it } from 'vitest';
import { checkWebRuntime, checkLiveEdge } from './runtime-checks.js';

it('runs portable checks and validates the edge credential guard', async () => {
    const results = await checkWebRuntime();
    expect(results).toHaveLength(7);
    expect(results).toContain(
        'Storage signing, streaming, resumable uploads, retries, CRC32C, and progress'
    );
    await expect(checkLiveEdge({} as never)).rejects.toThrow('configuration');
});
