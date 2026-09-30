import type { FirebaseAdminAuth } from './firebase-admin-auth.js';
import { FirebaseEdgeError } from './errors.js';

/** Enabled standard sign-in provider, without OAuth credentials. */
export interface IdentityProvider {
    providerId: string;
    enabled: true;
}

export class IdentityProviders {
    constructor(private readonly auth: FirebaseAdminAuth) {}

    /** Read all enabled standard providers for the configured project or tenant. */
    get() {
        return this.auth._getProviders();
    }
}

/** Validate a REST page and discard credentials before returning it. @internal */
export function parseIdentityProvidersPage(value: unknown): {
    providers: IdentityProvider[];
    nextPageToken?: string;
} {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new FirebaseEdgeError({
            code: 'auth/internal-error',
            message: 'Invalid provider list response.'
        });
    }
    const { defaultSupportedIdpConfigs = [], nextPageToken } = value as Record<
        string,
        unknown
    >;
    if (
        !Array.isArray(defaultSupportedIdpConfigs) ||
        (nextPageToken !== undefined && typeof nextPageToken !== 'string')
    ) {
        throw new FirebaseEdgeError({
            code: 'auth/internal-error',
            message: 'Invalid provider list response.'
        });
    }
    const providers: IdentityProvider[] = [];
    for (const config of defaultSupportedIdpConfigs) {
        if (
            !config ||
            typeof config !== 'object' ||
            Array.isArray(config) ||
            typeof config.name !== 'string' ||
            !/^projects\/[^/]+\/(?:tenants\/[^/]+\/)?defaultSupportedIdpConfigs\/[^/]+$/.test(
                config.name
            ) ||
            (config.enabled !== undefined &&
                typeof config.enabled !== 'boolean')
        ) {
            throw new FirebaseEdgeError({
                code: 'auth/internal-error',
                message: 'Invalid provider configuration response.'
            });
        }
        if (config.enabled === true) {
            providers.push({
                providerId: config.name.split('/').at(-1)!,
                enabled: true
            });
        }
    }
    return { providers, nextPageToken };
}
