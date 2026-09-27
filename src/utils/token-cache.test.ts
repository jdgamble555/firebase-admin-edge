import { afterEach, expect, it, vi } from 'vitest';
import { TokenCache } from './token-cache.js';

afterEach(() => vi.useRealTimers());

it('expires at the TTL boundary, including zero TTL', () => {
    vi.useFakeTimers();
    vi.setSystemTime(1000);
    const cache = new TokenCache();
    cache.set('token', 'value', 100);
    vi.setSystemTime(1099);
    expect(cache.get('token')).toBe('value');
    vi.setSystemTime(1100);
    expect(cache.get('token')).toBeUndefined();
    expect(cache.has('token')).toBe(false);
    cache.set('zero', 'value', 0);
    expect(cache.get('zero')).toBeUndefined();
});
