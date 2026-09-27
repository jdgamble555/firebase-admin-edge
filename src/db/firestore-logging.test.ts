import { afterEach, expect, it, vi } from 'vitest';
import {
    setLogFunction,
    logFirestore,
    GrpcStatus
} from './firestore-logging.js';
afterEach(() => setLogFunction(null));
it('supports replaceable logging, disabling and failure isolation', () => {
    const logger = vi.fn();
    setLogFunction(logger);
    logFirestore('request completed');
    expect(logger).toHaveBeenCalledWith('request completed');
    setLogFunction(null);
    logFirestore('disabled');
    expect(logger).toHaveBeenCalledOnce();
    setLogFunction(() => {
        throw new Error('logger failed');
    });
    expect(() => logFirestore('safe')).not.toThrow();
    expect(() => setLogFunction('bad' as never)).toThrow();
    expect(GrpcStatus.ABORTED).toBe(10);
    expect(GrpcStatus.UNAVAILABLE).toBe(14);
});
