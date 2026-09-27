import { afterEach, describe, expect, it, vi } from 'vitest';
import { resolveAuthEmulatorHost } from './auth-emulator.js';

afterEach(() => vi.unstubAllEnvs());

describe('resolveAuthEmulatorHost', () => {
    it('reads the environment and supports explicit overrides and production opt-out', () => {
        vi.stubEnv('FIREBASE_AUTH_EMULATOR_HOST', 'localhost:9099');
        expect(resolveAuthEmulatorHost()).toBe('localhost:9099');
        expect(resolveAuthEmulatorHost('127.0.0.1:9199')).toBe(
            '127.0.0.1:9199'
        );
        expect(resolveAuthEmulatorHost(null)).toBeNull();
        vi.stubEnv('FIREBASE_AUTH_EMULATOR_HOST', '');
        expect(resolveAuthEmulatorHost()).toBeNull();
    });

    it('works without a Node process global', () => {
        const original = globalThis.process;
        try {
            Object.defineProperty(globalThis, 'process', {
                value: undefined,
                configurable: true,
                writable: true
            });
            expect(resolveAuthEmulatorHost()).toBeNull();
            expect(resolveAuthEmulatorHost('[::1]:9099')).toBe('[::1]:9099');
        } finally {
            Object.defineProperty(globalThis, 'process', {
                value: original,
                configurable: true,
                writable: true
            });
        }
    });

    it.each([
        '',
        'localhost',
        'http://localhost:9099',
        'https://localhost:9099',
        'localhost:9099/',
        'localhost:9099/path',
        'user@localhost:9099',
        'localhost:9099?x=1',
        'localhost:9099#x',
        'localhost:0',
        'localhost:65536',
        'localhost:abc',
        ' localhost:9099',
        'localhost:9099\\x',
        '[invalid]:9099'
    ])('rejects invalid host %s', (host) => {
        expect(() => resolveAuthEmulatorHost(host)).toThrow();
    });

    it('rejects malformed environment configuration instead of falling back to production', () => {
        vi.stubEnv('FIREBASE_AUTH_EMULATOR_HOST', 'http://localhost:9099');
        expect(() => resolveAuthEmulatorHost()).toThrow();
    });
});
