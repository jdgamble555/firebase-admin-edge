import { expect, it } from 'vitest';
import { FirebaseEdgeError } from '../auth/errors.js';
import {
    remoteConfigError,
    invalidRemoteConfig,
    isRemoteConfigObject
} from './remote-config-results.js';

it('preserves Firebase errors and wraps unexpected failures', () => {
    const original = new FirebaseEdgeError({
        message: 'failure',
        code: 'remote-config/unavailable'
    });
    expect(remoteConfigError(original)).toBe(original);
    expect(remoteConfigError(new Error('failure')).cause).toBeInstanceOf(Error);
    expect(() => invalidRemoteConfig('bad argument')).toThrow('bad argument');
});

it('accepts records and rejects null and arrays', () => {
    expect(isRemoteConfigObject({})).toBe(true);
    for (const value of [null, undefined, [], 1, 'text']) {
        expect(isRemoteConfigObject(value)).toBe(false);
    }
});
