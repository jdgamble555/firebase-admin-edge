import { describe, expect, it } from 'vitest';
import {
    buildAuthConfigRequest,
    configUpdateMask,
    invalidConfig,
    parseAuthConfigResponse,
    validateTenantId
} from './auth-config.js';
import type { AuthConfigOperation } from './auth-config-types.js';

describe('configuration conversion', () => {
    it('allows ten tenant test numbers and rejects an eleventh', () => {
        const testPhoneNumbers = Object.fromEntries(
            Array.from({ length: 10 }, (_, index) => [
                `+155555501${String(index).padStart(2, '0')}`,
                '123456'
            ])
        );
        const operation: AuthConfigOperation = {
            resource: 'tenant',
            action: 'update',
            id: 'tenant-a',
            properties: { testPhoneNumbers }
        };
        expect(buildAuthConfigRequest(operation)).toEqual({ testPhoneNumbers });
        testPhoneNumbers['+15555550110'] = '123456';
        expect(() => buildAuthConfigRequest(operation)).toThrow(
            'Invalid test phone numbers.'
        );
    });

    it('supports clearing display names and partially updating response types', () => {
        expect(
            buildAuthConfigRequest({
                resource: 'provider',
                action: 'update',
                id: 'oidc.a',
                properties: {
                    displayName: '',
                    responseType: { idToken: false }
                }
            })
        ).toEqual({ displayName: '', responseType: { idToken: false } });
    });

    it.each([
        { passwordPolicyConfig: { constraints: { minLength: 6.5 } } },
        {
            multiFactorConfig: {
                providerConfigs: [
                    { totpProviderConfig: { adjacentIntervals: 1.5 } }
                ]
            }
        },
        { recaptchaConfig: { managedRules: 'bad' } },
        { emailPrivacyConfig: null }
    ])('rejects invalid nested settings %j', (properties) => {
        expect(() =>
            buildAuthConfigRequest({
                resource: 'project',
                action: 'update',
                properties
            })
        ).toThrow();
    });

    it('rejects invalid URLs, missing code-flow secrets, and malformed resource responses', () => {
        expect(() =>
            buildAuthConfigRequest({
                resource: 'provider',
                action: 'update',
                id: 'oidc.a',
                properties: { issuer: 'https://[' }
            })
        ).toThrow();
        expect(() =>
            buildAuthConfigRequest({
                resource: 'provider',
                action: 'update',
                id: 'oidc.a',
                properties: { responseType: { code: true } }
            })
        ).toThrow();
        expect(() =>
            parseAuthConfigResponse(
                { resource: 'provider', action: 'get' },
                { name: 'projects/p/oauthIdpConfigs/oidc.a' }
            )
        ).toThrow();
        expect(() =>
            parseAuthConfigResponse(
                { resource: 'tenant', action: 'get' },
                { name: 'projects/p/providers/t' }
            )
        ).toThrow();
        expect(() =>
            parseAuthConfigResponse(
                { resource: 'provider', action: 'get' },
                {
                    name: 'projects/p/providers/oidc.a',
                    clientId: 'client',
                    issuer: 'https://example.com'
                }
            )
        ).toThrow();
    });
    it('creates structured validation errors and validates tenant IDs', () => {
        expect(invalidConfig('bad')).toMatchObject({
            code: 'auth/invalid-argument',
            message: 'bad'
        });
        expect(() => validateTenantId('tenant-1')).not.toThrow();
        for (const id of ['', '../other', '.', '..', 'a b', 'a?b', null])
            expect(() => validateTenantId(id as string)).toThrow();
    });

    it('translates SAML fields and generates leaf masks', () => {
        const operation: AuthConfigOperation = {
            resource: 'provider',
            action: 'create',
            id: 'saml.example',
            properties: {
                providerId: 'saml.example',
                enabled: false,
                idpEntityId: 'idp',
                ssoURL: 'https://idp.example/sso',
                x509Certificates: ['certificate'],
                rpEntityId: 'rp',
                callbackURL: 'https://app.example/callback',
                enableRequestSigning: true
            }
        };
        const body = buildAuthConfigRequest(operation)!;
        expect(body).toEqual({
            enabled: false,
            idpConfig: {
                idpEntityId: 'idp',
                ssoUrl: 'https://idp.example/sso',
                idpCertificates: [{ x509Certificate: 'certificate' }],
                signRequest: true
            },
            spConfig: {
                spEntityId: 'rp',
                callbackUri: 'https://app.example/callback'
            }
        });
        expect(configUpdateMask(body)).toContain('idpConfig.signRequest');
        const response = parseAuthConfigResponse(
            { ...operation, action: 'get' },
            { ...body, name: 'projects/p/inboundSamlConfigs/saml.example' }
        );
        expect(response).toEqual(operation.properties);
        const signing = buildAuthConfigRequest({
            resource: 'provider',
            action: 'update',
            id: 'saml.example',
            properties: { enableRequestSigning: false }
        });
        expect(signing).toEqual({ idpConfig: { signRequest: false } });
    });

    it('round trips OIDC fields and does not mutate input', () => {
        const properties = {
            providerId: 'oidc.example',
            enabled: true,
            clientId: 'client',
            issuer: 'https://idp.example',
            clientSecret: 'secret',
            responseType: { code: true, idToken: false }
        };
        const operation: AuthConfigOperation = {
            resource: 'provider',
            action: 'create',
            id: properties.providerId,
            properties
        };
        const body = buildAuthConfigRequest(operation);
        expect(body).not.toHaveProperty('providerId');
        expect(properties.providerId).toBe('oidc.example');
        const result = parseAuthConfigResponse(operation, {
            ...body,
            name: 'projects/p/oauthIdpConfigs/oidc.example'
        });
        expect(result).toEqual(properties);
    });

    it('converts project security settings in both directions', () => {
        const properties = {
            multiFactorConfig: {
                state: 'ENABLED',
                factorIds: ['phone'],
                providerConfigs: [
                    {
                        state: 'ENABLED',
                        totpProviderConfig: { adjacentIntervals: 2 }
                    }
                ]
            },
            smsRegionConfig: { allowlistOnly: { allowedRegions: ['US'] } },
            recaptchaConfig: {
                phoneEnforcementState: 'AUDIT',
                smsTollFraudManagedRules: [{ startScore: 0.7, action: 'BLOCK' }]
            },
            passwordPolicyConfig: {
                enforcementState: 'ENFORCE',
                forceUpgradeOnSignin: false,
                constraints: { minLength: 12, requireNumeric: true }
            },
            emailPrivacyConfig: { enableImprovedEmailPrivacy: true },
            mobileLinksConfig: { domain: 'HOSTING_DOMAIN' }
        };
        const operation: AuthConfigOperation = {
            resource: 'project',
            action: 'update',
            properties
        };
        const body = buildAuthConfigRequest(operation)!;
        expect(body).toMatchObject({
            mfa: { enabledProviders: ['PHONE_SMS'] },
            recaptchaConfig: {
                tollFraudManagedRules: [{ startScore: 0.7, action: 'BLOCK' }]
            },
            passwordPolicyConfig: {
                passwordPolicyEnforcementState: 'ENFORCE',
                passwordPolicyVersions: [
                    {
                        customStrengthOptions: {
                            minPasswordLength: 12,
                            containsNumericCharacter: true
                        }
                    }
                ]
            }
        });
        expect(parseAuthConfigResponse(operation, body)).toEqual(properties);
        expect(configUpdateMask(body)).toContain(
            'passwordPolicyConfig.passwordPolicyVersions'
        );
    });

    it('converts tenant email, anonymous, MFA, and phone settings', () => {
        const properties = {
            displayName: 'Example',
            emailSignInConfig: { enabled: false, passwordRequired: true },
            anonymousSignInEnabled: false,
            multiFactorConfig: { factorIds: [] },
            testPhoneNumbers: null
        };
        const operation: AuthConfigOperation = {
            resource: 'tenant',
            action: 'update',
            id: 't',
            properties
        };
        const body = buildAuthConfigRequest(operation)!;
        expect(body).toEqual({
            displayName: 'Example',
            allowPasswordSignup: false,
            enableEmailLinkSignin: false,
            enableAnonymousUser: false,
            mfaConfig: { enabledProviders: [] },
            testPhoneNumbers: {}
        });
        expect(configUpdateMask(body)).toContain('testPhoneNumbers');
        expect(
            parseAuthConfigResponse(operation, {
                ...body,
                name: 'projects/p/tenants/t'
            })
        ).toEqual({ ...properties, tenantId: 't', testPhoneNumbers: {} });
        expect(
            configUpdateMask({ testPhoneNumbers: { '+15555555555': '123456' } })
        ).toEqual(['testPhoneNumbers']);
    });

    it.each(['oidc', 'saml'] as const)(
        'parses %s pagination, empty pages and defaults',
        (type) => {
            const op: AuthConfigOperation = {
                resource: 'provider',
                action: 'list',
                type
            };
            const key =
                type === 'oidc' ? 'oauthIdpConfigs' : 'inboundSamlConfigs';
            expect(parseAuthConfigResponse(op, {})).toEqual({
                providerConfigs: []
            });
            expect(
                parseAuthConfigResponse(op, {
                    [key]: [
                        {
                            name: `projects/p/${key}/${type}.example`,
                            clientId: 'client',
                            issuer: 'https://idp.example',
                            idpConfig: {
                                idpEntityId: 'idp',
                                ssoUrl: 'https://idp.example'
                            },
                            spConfig: { spEntityId: 'rp' }
                        }
                    ],
                    nextPageToken: 'next'
                })
            ).toEqual({
                providerConfigs: [
                    {
                        providerId: `${type}.example`,
                        enabled: false,
                        ...(type === 'oidc'
                            ? {
                                  clientId: 'client',
                                  issuer: 'https://idp.example'
                              }
                            : {
                                  idpEntityId: 'idp',
                                  ssoURL: 'https://idp.example',
                                  rpEntityId: 'rp',
                                  x509Certificates: []
                              })
                    }
                ],
                pageToken: 'next'
            });
            expect(() => parseAuthConfigResponse(op, { [key]: {} })).toThrow();
        }
    );

    it('parses tenant pages, project empty config, and successful deletion', () => {
        expect(
            parseAuthConfigResponse(
                { resource: 'tenant', action: 'list' },
                {
                    tenants: [{ name: 'projects/p/tenants/t' }],
                    nextPageToken: 'next'
                }
            )
        ).toEqual({
            tenants: [
                {
                    tenantId: 't',
                    anonymousSignInEnabled: false,
                    emailSignInConfig: {
                        enabled: false,
                        passwordRequired: true
                    }
                }
            ],
            pageToken: 'next'
        });
        expect(
            parseAuthConfigResponse({ resource: 'project', action: 'get' }, {})
        ).toEqual({});
        expect(
            parseAuthConfigResponse(
                { resource: 'provider', action: 'delete' },
                null
            )
        ).toBeUndefined();
        for (const input of [
            null,
            [],
            'bad',
            {},
            { name: 'bad' },
            { name: 'projects/p/providers/google.com' }
        ])
            expect(() =>
                parseAuthConfigResponse(
                    { resource: 'provider', action: 'get' },
                    input
                )
            ).toThrow();
    });

    it.each([
        { resource: 'provider', action: 'get', id: 'google.com' },
        { resource: 'provider', action: 'get', id: 'oidc.' },
        { resource: 'provider', action: 'get', id: 'saml.a/b' },
        { resource: 'provider', action: 'list', type: 'other' },
        { resource: 'provider', action: 'list', type: 'oidc', maxResults: 101 },
        { resource: 'tenant', action: 'list', maxResults: 1001 },
        { resource: 'tenant', action: 'list', maxResults: 0 },
        { resource: 'tenant', action: 'list', maxResults: 1.5 },
        { resource: 'tenant', action: 'list', pageToken: '' },
        { resource: 'tenant', action: 'get', id: '' },
        { resource: 'project', action: 'update', properties: null },
        { resource: 'project', action: 'update', properties: [] },
        { resource: 'project', action: 'update', properties: {} },
        {
            resource: 'project',
            action: 'update',
            properties: { unknown: true }
        },
        {
            resource: 'tenant',
            action: 'create',
            properties: { anonymousSignInEnabled: 'yes' }
        },
        {
            resource: 'tenant',
            action: 'create',
            properties: { testPhoneNumbers: { bad: '123' } }
        },
        {
            resource: 'provider',
            action: 'create',
            id: 'oidc.a',
            properties: { clientId: 'a' }
        },
        {
            resource: 'provider',
            action: 'create',
            id: 'saml.a',
            properties: {
                idpEntityId: 'a',
                ssoURL: 'https://a.com',
                x509Certificates: [],
                rpEntityId: 'a'
            }
        },
        {
            resource: 'provider',
            action: 'update',
            id: 'oidc.a',
            properties: { issuer: 'bad' }
        },
        {
            resource: 'provider',
            action: 'update',
            id: 'oidc.a',
            properties: { providerId: 'oidc.b' }
        },
        {
            resource: 'provider',
            action: 'update',
            id: 'oidc.a',
            properties: { responseType: { code: true, idToken: true } }
        },
        {
            resource: 'provider',
            action: 'create',
            id: 'oidc.a',
            properties: {
                clientId: 'a',
                issuer: 'https://a.com',
                responseType: { code: true }
            }
        },
        {
            resource: 'provider',
            action: 'update',
            id: 'saml.a',
            properties: { x509Certificates: [1] }
        },
        {
            resource: 'project',
            action: 'update',
            properties: { multiFactorConfig: { factorIds: ['totp'] } }
        },
        {
            resource: 'project',
            action: 'update',
            properties: { multiFactorConfig: { state: 'bad' } }
        },
        {
            resource: 'project',
            action: 'update',
            properties: {
                passwordPolicyConfig: { constraints: { minLength: 1 } }
            }
        },
        {
            resource: 'project',
            action: 'update',
            properties: { smsRegionConfig: {} }
        }
    ])('rejects invalid configuration %j', (operation) => {
        expect(() =>
            buildAuthConfigRequest(operation as AuthConfigOperation)
        ).toThrow();
    });
});
