import { FirebaseEdgeError } from './errors.js';
import type { AuthConfigOperation } from './auth-config-types.js';

type Fields = Record<string, unknown>;
type Rule = {
    path?: string;
    kind?: 'string' | 'boolean' | 'number' | 'url' | 'strings';
    values?: readonly unknown[];
    children?: Schema;
    array?: Schema;
    min?: number;
    max?: number;
    integer?: boolean;
    allowEmpty?: boolean;
};
type Schema = Record<string, Rule>;
const boolean: Rule = { kind: 'boolean' };
const string: Rule = { kind: 'string' };
const state: Rule = { values: ['ENABLED', 'DISABLED'] };
const commonProvider: Schema = {
    enabled: boolean,
    displayName: { ...string, allowEmpty: true }
};
const oidc: Schema = {
    ...commonProvider,
    clientId: string,
    issuer: { kind: 'url' },
    clientSecret: string,
    responseType: { children: { code: boolean, idToken: boolean } }
};
const saml: Schema = {
    ...commonProvider,
    idpEntityId: { ...string, path: 'idpConfig.idpEntityId' },
    ssoURL: { kind: 'url', path: 'idpConfig.ssoUrl' },
    x509Certificates: { kind: 'strings', path: 'idpConfig.idpCertificates' },
    enableRequestSigning: { ...boolean, path: 'idpConfig.signRequest' },
    rpEntityId: { ...string, path: 'spConfig.spEntityId' },
    callbackURL: { kind: 'url', path: 'spConfig.callbackUri' }
};
const project: Schema = {
    smsRegionConfig: {
        children: {
            allowByDefault: {
                children: { disallowedRegions: { kind: 'strings' } }
            },
            allowlistOnly: { children: { allowedRegions: { kind: 'strings' } } }
        }
    },
    multiFactorConfig: {
        path: 'mfa',
        children: {
            state,
            factorIds: { kind: 'strings', path: 'enabledProviders' },
            providerConfigs: {
                array: {
                    state,
                    totpProviderConfig: {
                        children: {
                            adjacentIntervals: {
                                kind: 'number',
                                min: 0,
                                max: 10,
                                integer: true
                            }
                        }
                    }
                }
            }
        }
    },
    recaptchaConfig: {
        children: {
            emailPasswordEnforcementState: {
                values: ['OFF', 'AUDIT', 'ENFORCE']
            },
            phoneEnforcementState: { values: ['OFF', 'AUDIT', 'ENFORCE'] },
            managedRules: {
                array: {
                    endScore: { kind: 'number', min: 0, max: 1 },
                    action: { values: ['BLOCK'] }
                }
            },
            recaptchaKeys: {
                array: {
                    key: string,
                    type: { values: ['WEB', 'ANDROID', 'IOS'] }
                }
            },
            useAccountDefender: boolean,
            useSmsBotScore: boolean,
            useSmsTollFraudProtection: boolean,
            smsTollFraudManagedRules: {
                path: 'tollFraudManagedRules',
                array: {
                    startScore: { kind: 'number', min: 0, max: 1 },
                    action: { values: ['BLOCK'] }
                }
            }
        }
    },
    passwordPolicyConfig: {
        children: {
            enforcementState: {
                path: 'passwordPolicyEnforcementState',
                values: ['OFF', 'ENFORCE']
            },
            forceUpgradeOnSignin: boolean,
            constraints: {
                path: 'passwordPolicyVersions',
                children: {
                    requireUppercase: {
                        ...boolean,
                        path: 'containsUppercaseCharacter'
                    },
                    requireLowercase: {
                        ...boolean,
                        path: 'containsLowercaseCharacter'
                    },
                    requireNonAlphanumeric: {
                        ...boolean,
                        path: 'containsNonAlphanumericCharacter'
                    },
                    requireNumeric: {
                        ...boolean,
                        path: 'containsNumericCharacter'
                    },
                    minLength: {
                        kind: 'number',
                        min: 6,
                        max: 30,
                        integer: true,
                        path: 'minPasswordLength'
                    },
                    maxLength: {
                        kind: 'number',
                        min: 6,
                        max: 4096,
                        integer: true,
                        path: 'maxPasswordLength'
                    }
                }
            }
        }
    },
    emailPrivacyConfig: { children: { enableImprovedEmailPrivacy: boolean } },
    mobileLinksConfig: {
        children: {
            domain: {
                values: ['HOSTING_DOMAIN', 'FIREBASE_DYNAMIC_LINK_DOMAIN']
            }
        }
    }
};
const { mobileLinksConfig: _mobile, ...tenantProject } = project;
const tenant: Schema = {
    ...tenantProject,
    multiFactorConfig: { ...project.multiFactorConfig, path: 'mfaConfig' },
    displayName: string,
    anonymousSignInEnabled: { ...boolean, path: 'enableAnonymousUser' },
    emailSignInConfig: {
        path: '',
        children: {
            enabled: { ...boolean, path: 'allowPasswordSignup' },
            passwordRequired: { ...boolean, path: 'enableEmailLinkSignin' }
        }
    },
    testPhoneNumbers: {}
};

/** @internal */
export function invalidConfig(message: string): FirebaseEdgeError {
    return new FirebaseEdgeError({ code: 'auth/invalid-argument', message });
}

/** @internal */
export function validateTenantId(id: string): void {
    if (
        typeof id !== 'string' ||
        !id.length ||
        /[\/\s?#]/.test(id) ||
        id === '.' ||
        id === '..'
    )
        throw invalidConfig(
            'A non-empty tenant ID without path separators is required.'
        );
}

/** Convert only known fields, preserving omitted fields and explicit false/empty arrays. */
function convertFields(input: Fields, schema: Schema, reading = false): Fields {
    if (!input || typeof input !== 'object' || Array.isArray(input))
        throw invalidConfig('Configuration must be an object.');
    if (
        !reading &&
        Object.keys(input).some((key) => !Object.hasOwn(schema, key))
    )
        throw invalidConfig('Unknown configuration field.');
    const output: Fields = {};
    for (const [key, rule] of Object.entries(schema)) {
        const path = (rule.path ?? key).split('.').filter(Boolean);
        let value: any = reading ? input : input[key];
        if (reading) for (const part of path) value = value?.[part];
        if (value === undefined) continue;
        if (
            reading &&
            key === 'emailSignInConfig' &&
            input.allowPasswordSignup === undefined &&
            input.enableEmailLinkSignin === undefined
        )
            continue;
        if (reading && key === 'constraints')
            value = value?.[0]?.customStrengthOptions;
        if (value === undefined) continue;
        if (reading && key === 'x509Certificates')
            value = value.map((cert: Fields) => cert.x509Certificate);
        if (reading && key === 'factorIds')
            value = value
                .filter((factor: string) => factor === 'PHONE_SMS')
                .map(() => 'phone');
        if (!reading) {
            if (rule.values && !rule.values.includes(value))
                throw invalidConfig(`Invalid ${key}.`);
            if (rule.kind === 'boolean' && typeof value !== 'boolean')
                throw invalidConfig(`${key} must be boolean.`);
            if (
                (rule.kind === 'string' || rule.kind === 'url') &&
                (typeof value !== 'string' ||
                    (!value.length && !rule.allowEmpty))
            )
                throw invalidConfig(`${key} must be a non-empty string.`);
            if (rule.kind === 'url') {
                if (
                    !URL.canParse(value) ||
                    !['http:', 'https:'].includes(new URL(value).protocol)
                )
                    throw invalidConfig(`${key} must be an HTTP(S) URL.`);
            }
            if (
                rule.kind === 'number' &&
                (typeof value !== 'number' ||
                    !Number.isFinite(value) ||
                    (rule.integer && !Number.isInteger(value)) ||
                    value < (rule.min ?? -Infinity) ||
                    value > (rule.max ?? Infinity))
            )
                throw invalidConfig(`Invalid ${key}.`);
            if (
                rule.kind === 'strings' &&
                (!Array.isArray(value) ||
                    value.some(
                        (item) => typeof item !== 'string' || !item.length
                    ))
            )
                throw invalidConfig(`${key} must be an array of strings.`);
            if (
                key === 'factorIds' &&
                value.some((factor: string) => factor !== 'phone')
            )
                throw invalidConfig('Only the phone factor ID is supported.');
            if (
                key === 'responseType' &&
                (!value ||
                    typeof value !== 'object' ||
                    (Object.keys(value).length > 1 &&
                        !!value.code === !!value.idToken))
            )
                throw invalidConfig('Enable exactly one OIDC response type.');
            if (
                key === 'smsRegionConfig' &&
                (!value || !!value.allowByDefault === !!value.allowlistOnly)
            )
                throw invalidConfig('Choose exactly one SMS region policy.');
            if (key === 'testPhoneNumbers') {
                if (
                    value !== null &&
                    (typeof value !== 'object' ||
                        Array.isArray(value) ||
                        Object.keys(value).length > 10 ||
                        Object.entries(value).some(
                            ([phone, code]) =>
                                !/^\+[1-9]\d{1,14}$/.test(phone) ||
                                typeof code !== 'string' ||
                                !/^\d{6}$/.test(code)
                        ))
                )
                    throw invalidConfig('Invalid test phone numbers.');
                value = value ?? {};
            }
        }
        if (rule.children) value = convertFields(value, rule.children, reading);
        if (rule.array) {
            if (!Array.isArray(value))
                throw invalidConfig(`${key} must be an array.`);
            value = value.map((item) =>
                convertFields(item, rule.array!, reading)
            );
        }
        if (key === 'passwordRequired') value = !value;
        if (!reading && key === 'constraints')
            value = [{ customStrengthOptions: value }];
        if (!reading && key === 'x509Certificates')
            value = value.map((certificate: string) => ({
                x509Certificate: certificate
            }));
        if (!reading && key === 'factorIds')
            value = value.map(() => 'PHONE_SMS');
        if (reading) {
            output[key] = value;
            continue;
        }
        if (path.length === 0) {
            Object.assign(output, value);
            continue;
        }
        let target = output;
        for (const part of path.slice(0, -1))
            target = (target[part] ??= {}) as Fields;
        target[path[path.length - 1]!] = value;
    }
    return output;
}

/** Validate before obtaining credentials, and convert public properties to API fields. @internal */
export function buildAuthConfigRequest(
    operation: AuthConfigOperation
): Fields | undefined {
    const { resource, action, id, properties } = operation;
    if (
        resource === 'provider' &&
        action !== 'list' &&
        (typeof id !== 'string' || !/^(oidc|saml)\.[^\s/\?#]+$/.test(id))
    )
        throw invalidConfig(
            'Provider ID must start with oidc. or saml. and contain a suffix.'
        );
    if (resource === 'tenant' && action !== 'create' && action !== 'list')
        validateTenantId(id!);
    if (action === 'list') {
        if (
            resource === 'provider' &&
            operation.type !== 'oidc' &&
            operation.type !== 'saml'
        )
            throw invalidConfig('Provider type must be oidc or saml.');
        const limit = resource === 'provider' ? 100 : 1000;
        if (
            operation.maxResults !== undefined &&
            (!Number.isInteger(operation.maxResults) ||
                operation.maxResults < 1 ||
                operation.maxResults > limit)
        )
            throw invalidConfig(`maxResults must be between 1 and ${limit}.`);
        if (
            operation.pageToken !== undefined &&
            (typeof operation.pageToken !== 'string' ||
                !operation.pageToken.length)
        )
            throw invalidConfig('pageToken must be a non-empty string.');
    }
    if (action !== 'create' && action !== 'update') return undefined;
    if (
        !properties ||
        typeof properties !== 'object' ||
        Array.isArray(properties)
    )
        throw invalidConfig('Configuration must be an object.');
    const fields = { ...properties } as Fields;
    if (resource === 'provider' && action === 'create')
        delete fields.providerId;
    const schema =
        resource === 'project'
            ? project
            : resource === 'tenant'
              ? tenant
              : id!.startsWith('oidc.')
                ? oidc
                : saml;
    if (resource === 'provider' && action === 'create') {
        const required = id!.startsWith('oidc.')
            ? ['clientId', 'issuer']
            : ['idpEntityId', 'ssoURL', 'x509Certificates', 'rpEntityId'];
        for (const field of required)
            if (fields[field] === undefined)
                throw invalidConfig(`${field} is required.`);
        if (
            Array.isArray(fields.x509Certificates) &&
            fields.x509Certificates.length === 0
        )
            throw invalidConfig('At least one SAML certificate is required.');
    }
    if (
        resource === 'provider' &&
        (fields.responseType as Fields | undefined)?.code &&
        !fields.clientSecret
    )
        throw invalidConfig('Code flow requires a client secret.');
    const body = convertFields(fields, schema);
    if (action === 'update' && !Object.keys(body).length)
        throw invalidConfig('At least one update is required.');
    return body;
}

/** Build a leaf mask so partial nested updates do not erase sibling settings. @internal */
export function configUpdateMask(body: Fields, prefix = ''): string[] {
    return Object.entries(body).flatMap(([key, value]) => {
        const path = prefix ? `${prefix}.${key}` : key;
        if (
            !value ||
            typeof value !== 'object' ||
            Array.isArray(value) ||
            key === 'testPhoneNumbers' ||
            !Object.keys(value).length
        )
            return [path];
        return configUpdateMask(value as Fields, path);
    });
}

/** Parse resource and pagination envelopes into public configuration objects. @internal */
export function parseAuthConfigResponse(
    operation: AuthConfigOperation,
    input: unknown
): unknown {
    if (operation.action === 'delete') return undefined;
    if (!input || typeof input !== 'object' || Array.isArray(input))
        throw invalidConfig('Invalid configuration response.');
    const data = input as Fields;
    if (operation.action === 'list') {
        const key =
            operation.resource === 'tenant'
                ? 'tenants'
                : operation.type === 'oidc'
                  ? 'oauthIdpConfigs'
                  : 'inboundSamlConfigs';
        const items = data[key] ?? [];
        if (
            !Array.isArray(items) ||
            (data.nextPageToken !== undefined &&
                typeof data.nextPageToken !== 'string')
        )
            throw invalidConfig('Invalid list response.');
        const values = items.map((item) =>
            parseAuthConfigResponse({ ...operation, action: 'get' }, item)
        );
        return {
            [operation.resource === 'tenant' ? 'tenants' : 'providerConfigs']:
                values,
            ...(data.nextPageToken && { pageToken: data.nextPageToken })
        };
    }
    if (operation.resource === 'project')
        return convertFields(data, project, true);
    if (typeof data.name !== 'string' || !data.name.includes('/'))
        throw invalidConfig('Missing configuration resource name.');
    const id = data.name.split('/').pop()!;
    if (operation.resource === 'tenant') {
        validateTenantId(id);
        if (!data.name.endsWith(`/tenants/${id}`))
            throw invalidConfig('Invalid tenant resource name.');
        return {
            ...convertFields(data, tenant, true),
            tenantId: id,
            emailSignInConfig: {
                enabled: !!data.allowPasswordSignup,
                passwordRequired: !data.enableEmailLinkSignin
            },
            anonymousSignInEnabled: !!data.enableAnonymousUser
        };
    }
    if (!/^(oidc|saml)\..+/.test(id))
        throw invalidConfig('Invalid provider response.');
    const result = convertFields(
        data,
        id.startsWith('oidc.') ? oidc : saml,
        true
    );
    const collection = id.startsWith('oidc.')
        ? 'oauthIdpConfigs'
        : 'inboundSamlConfigs';
    if (!data.name.endsWith(`/${collection}/${id}`))
        throw invalidConfig('Invalid provider resource name.');
    const required = id.startsWith('oidc.')
        ? ['clientId', 'issuer']
        : ['idpEntityId', 'ssoURL', 'rpEntityId'];
    if (
        required.some(
            (field) => typeof result[field] !== 'string' || !result[field]
        )
    )
        throw invalidConfig('Incomplete provider response.');
    if (id.startsWith('saml.') && result.x509Certificates === undefined)
        result.x509Certificates = [];
    return { ...result, providerId: id, enabled: !!data.enabled };
}
