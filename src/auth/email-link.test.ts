import { afterEach, describe, expect, it, vi } from 'vitest';
import {
    createEmailLinkState,
    readEmailLinkState,
    parseEmailActionLink,
    parseEmailSignInLink
} from './email-link.js';

afterEach(() => vi.useRealTimers());
describe('email-link state', () => {
    it.each([undefined, 'user@example.com'])(
        'round-trips encrypted email=%s and redirect',
        async (email) => {
            const token = await createEmailLinkState(
                { email, next: '/dashboard' },
                'server-secret',
                'project',
                'tenant'
            );
            expect(token).not.toContain('user@example.com');
            const result = await readEmailLinkState(
                token,
                'server-secret',
                'project',
                'tenant'
            );
            expect(result).toEqual({ email, next: '/dashboard' });
        }
    );
    it.each(['key', 'project', 'tenant', 'tamper', 'expired'])(
        'rejects %s mismatches',
        async (mode) => {
            vi.useFakeTimers();
            const token = await createEmailLinkState(
                { email: 'a@b.com', next: '/' },
                'secret',
                'project',
                'tenant'
            );
            if (mode === 'expired') vi.setSystemTime(Date.now() + 3601000);
            const request = readEmailLinkState(
                mode === 'tamper' ? token + 'x' : token,
                mode === 'key' ? 'other' : 'secret',
                mode === 'project' ? 'other' : 'project',
                mode === 'tenant' ? 'other' : 'tenant'
            );
            await expect(request).rejects.toThrow();
        }
    );
    it.each(['//evil.com', 'https://evil.com', '/\\evil.com'])(
        'rejects unsafe redirects %s',
        async (next) => {
            const request = createEmailLinkState({ next }, 'secret', 'project');
            await expect(request).rejects.toThrow('local absolute');
        }
    );
    it('requires private server key material', async () => {
        const request = createEmailLinkState({ next: '/' }, '', 'project');
        await expect(request).rejects.toThrow('key material');
    });
});
describe('email-link parsing', () => {
    it.each(['direct', 'continue', 'wrapper'])('reads %s links', (kind) => {
        const url = new URL(
            'https://app/auth/email?mode=signIn&oobCode=code&apiKey=key&tenantId=tenant'
        );
        if (kind === 'direct') url.searchParams.set('emailLinkState', 'state');
        else
            url.searchParams.set(
                'continueUrl',
                'https://app/auth/email?emailLinkState=state'
            );
        const wrapper = new URL('https://host/link');
        wrapper.searchParams.set('link', url.toString());
        expect(
            parseEmailSignInLink(
                kind === 'wrapper' ? wrapper : url,
                'key',
                'tenant'
            )
        ).toEqual({ code: 'code', state: 'state' });
    });
    it.each([
        'mode=resetPassword&oobCode=x&emailLinkState=s',
        'mode=signIn&emailLinkState=s',
        'mode=signIn&oobCode=x',
        'mode=signIn&oobCode=x&emailLinkState=s&apiKey=wrong',
        'mode=signIn&oobCode=x&emailLinkState=s&tenantId=wrong'
    ])('rejects invalid links %s', (query) => {
        expect(() =>
            parseEmailSignInLink(new URL('https://app/?' + query), 'key')
        ).toThrow();
    });
});

describe('shared email action parsing', () => {
    it.each([
        'signIn',
        'resetPassword',
        'verifyAndChangeEmail',
        'verifyEmail',
        'recoverEmail'
    ])('inspects direct and wrapped %s without consuming it', (mode) => {
        const url = new URL(
            `https://app/callback?mode=${mode}&oobCode=code&apiKey=key&tenantId=tenant`
        );
        const wrapper = new URL('https://app/link');
        wrapper.searchParams.set('link', url.toString());
        expect(parseEmailActionLink(url, 'key', 'tenant')).toMatchObject({
            actionMode: mode,
            hasLink: true,
            code: 'code'
        });
        expect(parseEmailActionLink(wrapper, 'key', 'tenant')).toMatchObject({
            actionMode: mode,
            hasLink: true,
            code: 'code'
        });
    });
    it('leaves provider callbacks alone', () => {
        expect(
            parseEmailActionLink(
                new URL('https://app/callback?code=oauth&state=state'),
                'key'
            )
        ).toBeNull();
    });
    it.each([
        '?mode=resetPassword',
        '?emailLinkState=state',
        '?mode=signIn&oobCode='
    ])('describes incomplete links: %s', (query) => {
        expect(
            parseEmailActionLink(new URL('https://app/callback' + query), 'key')
        ).toMatchObject({ hasLink: false });
    });
    it.each([
        'mode=unknown&oobCode=code',
        'mode=resetPassword&oobCode=code&apiKey=wrong',
        'mode=verifyEmail&oobCode=code&tenantId=wrong',
        'link=not-a-url'
    ])('rejects invalid or mismatched links: %s', (query) => {
        expect(() =>
            parseEmailActionLink(
                new URL('https://app/callback?' + query),
                'key',
                'tenant'
            )
        ).toThrow();
    });
    it('rejects excessive wrapping', () => {
        let url = new URL(
            'https://app/callback?mode=resetPassword&oobCode=code'
        );
        for (let i = 0; i < 4; i++) {
            const wrapper = new URL('https://app/link');
            wrapper.searchParams.set('link', url.toString());
            url = wrapper;
        }
        expect(() => parseEmailActionLink(url, 'key')).toThrow();
    });
});
