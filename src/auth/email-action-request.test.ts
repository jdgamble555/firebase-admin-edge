import { describe, it, expect } from 'vitest';
import {
    buildEmailActionRequest,
    type ActionCodeSettings
} from './email-action-request.js';
import { FirebaseAdminAuthErrorInfo } from './errors.js';

describe('buildEmailActionRequest', () => {
    it('includes both addresses for verification before an email change', () => {
        expect(
            buildEmailActionRequest(
                'VERIFY_AND_CHANGE_EMAIL',
                'old@example.com',
                undefined,
                'new@example.com'
            )
        ).toEqual({
            data: {
                requestType: 'VERIFY_AND_CHANGE_EMAIL',
                email: 'old@example.com',
                newEmail: 'new@example.com',
                returnOobLink: true
            },
            error: null
        });
    });
    it.each([undefined, null, '', 'invalid', 'space @example.com', 123])(
        'rejects invalid new email %s',
        (newEmail) => {
            const result = buildEmailActionRequest(
                'VERIFY_AND_CHANGE_EMAIL',
                'old@example.com',
                undefined,
                newEmail as string
            );
            expect(result.data).toBeNull();
            expect(result.error?.code).toBe(
                FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT.code
            );
        }
    );
    it.each(['PASSWORD_RESET', 'VERIFY_EMAIL'] as const)(
        'supports %s without settings',
        (type) => {
            expect(buildEmailActionRequest(type, 'person@example.com')).toEqual(
                {
                    data: {
                        requestType: type,
                        email: 'person@example.com',
                        returnOobLink: true
                    },
                    error: null
                }
            );
        }
    );
    it('maps web and mobile settings without changing the input', () => {
        const settings: ActionCodeSettings = {
            url: 'https://example.com/finish',
            handleCodeInApp: true,
            iOS: { bundleId: 'com.example.ios' },
            android: {
                packageName: 'com.example.android',
                installApp: true,
                minimumVersion: '12'
            },
            linkDomain: 'links.example.com',
            dynamicLinkDomain: 'example.page.link'
        };
        const original = structuredClone(settings);
        expect(
            buildEmailActionRequest(
                'EMAIL_SIGNIN',
                'person@example.com',
                settings
            )
        ).toEqual({
            data: {
                requestType: 'EMAIL_SIGNIN',
                email: 'person@example.com',
                returnOobLink: true,
                continueUrl: settings.url,
                canHandleCodeInApp: true,
                iOSBundleId: 'com.example.ios',
                androidPackageName: 'com.example.android',
                androidInstallApp: true,
                androidMinimumVersion: '12',
                linkDomain: 'links.example.com',
                dynamicLinkDomain: 'example.page.link'
            },
            error: null
        });
        expect(settings).toEqual(original);
    });
    it('defaults optional boolean settings to false and omits absent fields', () => {
        expect(
            buildEmailActionRequest('VERIFY_EMAIL', 'person@example.com', {
                url: 'https://example.com',
                android: { packageName: 'com.example' }
            }).data
        ).toEqual({
            requestType: 'VERIFY_EMAIL',
            email: 'person@example.com',
            returnOobLink: true,
            continueUrl: 'https://example.com',
            canHandleCodeInApp: false,
            androidPackageName: 'com.example',
            androidInstallApp: false
        });
    });
    it('requires settings for sign-in', () => {
        expect(
            buildEmailActionRequest('EMAIL_SIGNIN', 'person@example.com').error
                ?.code
        ).toBe(FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT.code);
    });
    it.each([
        '',
        'missing-domain@',
        'no-at-sign',
        'space @example.com',
        null,
        1
    ])('rejects invalid email %s', (email) => {
        expect(
            buildEmailActionRequest('PASSWORD_RESET', email as string).error
                ?.code
        ).toBe(FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT.code);
    });
    it.each([
        null,
        [],
        'settings',
        {},
        { url: '' },
        { url: 5 },
        { url: 'not-a-url' },
        { url: 'javascript:alert(1)' },
        { handleCodeInApp: 'true' },
        { iOS: null },
        { iOS: {} },
        { iOS: { bundleId: '' } },
        { android: null },
        { android: {} },
        { android: { packageName: '' } },
        { android: { packageName: 'com.example', installApp: 1 } },
        { android: { packageName: 'com.example', minimumVersion: '' } },
        { linkDomain: '' },
        { linkDomain: 5 },
        { dynamicLinkDomain: '' }
    ])('returns a structured error for invalid settings %j', (invalid) => {
        const settings =
            invalid && typeof invalid === 'object' && !Array.isArray(invalid)
                ? { url: 'https://example.com', ...invalid }
                : invalid;
        // An empty settings object must still fail for its missing URL.
        const input =
            invalid &&
            typeof invalid === 'object' &&
            Object.keys(invalid).length === 0
                ? invalid
                : settings;
        const result = buildEmailActionRequest(
            'PASSWORD_RESET',
            'person@example.com',
            input as ActionCodeSettings
        );
        expect(result.data).toBeNull();
        expect(result.error?.code).toBe(
            FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT.code
        );
    });
});
