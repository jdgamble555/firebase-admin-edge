import { describe, expect, it } from 'vitest';
import {
    isLocalRedirectPath,
    parseProviderSession
} from './provider-session.js';

describe('provider session validation', () => {
    it.each(['/', '/dashboard', '/account?tab=providers#settings'])(
        'accepts local path %s',
        (path) => {
            expect(isLocalRedirectPath(path)).toBe(true);
        }
    );
    it.each([
        undefined,
        null,
        42,
        {},
        '',
        'relative',
        'https://example.com',
        '//example.com',
        '/\\example.com',
        '/\rredirect',
        '/\nredirect'
    ])('rejects unsafe path %s', (path) => {
        expect(isLocalRedirectPath(path)).toBe(false);
    });
    it.each(['signin', 'link'] as const)('reads a %s session', (intent) => {
        const flow = { sessionId: 'session', next: '/account', intent };
        expect(parseProviderSession(JSON.stringify(flow))).toEqual(flow);
    });
    it.each(['', 'not-json', 'null', '[]', '42', '"string"', '{}'])(
        'rejects malformed session %s',
        (stored) => {
            expect(parseProviderSession(stored)).toBeNull();
        }
    );
    it.each([
        { sessionId: '' },
        { sessionId: 1 },
        { sessionId: null },
        { next: '//external' },
        { next: '/\\external' },
        { next: '/\nexternal' },
        { next: null },
        { intent: 'other' },
        { intent: null }
    ])('rejects invalid session fields %j', (invalid) => {
        const stored = JSON.stringify({
            sessionId: 'session',
            next: '/',
            intent: 'signin',
            ...invalid
        });
        expect(parseProviderSession(stored)).toBeNull();
    });
});
