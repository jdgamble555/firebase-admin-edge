import type { FirebaseEdgeError } from './errors.js';

export type AuthConfigResult<T> =
    | { data: T; error: null }
    | { data: null; error: FirebaseEdgeError };
export interface BaseAuthProviderConfig {
    providerId: string;
    displayName?: string;
    enabled: boolean;
}
export interface OAuthResponseType {
    code?: boolean;
    idToken?: boolean;
}
export interface OIDCAuthProviderConfig extends BaseAuthProviderConfig {
    clientId: string;
    issuer: string;
    clientSecret?: string;
    responseType?: OAuthResponseType;
}
export interface SAMLAuthProviderConfig extends BaseAuthProviderConfig {
    idpEntityId: string;
    ssoURL: string;
    x509Certificates: string[];
    rpEntityId: string;
    callbackURL?: string;
    enableRequestSigning?: boolean;
}
export type AuthProviderConfig =
    | OIDCAuthProviderConfig
    | SAMLAuthProviderConfig;
export type OIDCUpdateAuthProviderRequest = Partial<
    Omit<OIDCAuthProviderConfig, 'providerId'>
>;
export type SAMLUpdateAuthProviderRequest = Partial<
    Omit<SAMLAuthProviderConfig, 'providerId'>
>;
export type UpdateAuthProviderRequest =
    | OIDCUpdateAuthProviderRequest
    | SAMLUpdateAuthProviderRequest;
export interface AuthProviderConfigFilter {
    type: 'oidc' | 'saml';
    maxResults?: number;
    pageToken?: string;
}
export interface ListProviderConfigResults {
    providerConfigs: AuthProviderConfig[];
    pageToken?: string;
}
export interface EmailSignInProviderConfig {
    enabled?: boolean;
    passwordRequired?: boolean;
}
export type MultiFactorConfigState = 'ENABLED' | 'DISABLED';
export interface TotpMultiFactorProviderConfig {
    adjacentIntervals?: number;
}
export interface MultiFactorProviderConfig {
    state: MultiFactorConfigState;
    totpProviderConfig?: TotpMultiFactorProviderConfig;
}
export interface MultiFactorConfig {
    state?: MultiFactorConfigState;
    factorIds?: 'phone'[];
    providerConfigs?: MultiFactorProviderConfig[];
}
export type SmsRegionConfig =
    | { allowByDefault: { disallowedRegions: string[] } }
    | { allowlistOnly: { allowedRegions: string[] } };
export type RecaptchaProviderEnforcementState = 'OFF' | 'AUDIT' | 'ENFORCE';
export interface RecaptchaConfig {
    emailPasswordEnforcementState?: RecaptchaProviderEnforcementState;
    phoneEnforcementState?: RecaptchaProviderEnforcementState;
    managedRules?: { endScore: number; action: 'BLOCK' }[];
    recaptchaKeys?: { key: string; type: 'WEB' | 'ANDROID' | 'IOS' }[];
    useAccountDefender?: boolean;
    useSmsBotScore?: boolean;
    useSmsTollFraudProtection?: boolean;
    smsTollFraudManagedRules?: { startScore: number; action: 'BLOCK' }[];
}
export interface CustomStrengthOptionsConfig {
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNonAlphanumeric?: boolean;
    requireNumeric?: boolean;
    minLength?: number;
    maxLength?: number;
}
export interface PasswordPolicyConfig {
    enforcementState?: 'OFF' | 'ENFORCE';
    forceUpgradeOnSignin?: boolean;
    constraints?: CustomStrengthOptionsConfig;
}
export interface EmailPrivacyConfig {
    enableImprovedEmailPrivacy?: boolean;
}
export interface MobileLinksConfig {
    domain?: 'HOSTING_DOMAIN' | 'FIREBASE_DYNAMIC_LINK_DOMAIN';
}
export interface UpdateProjectConfigRequest {
    smsRegionConfig?: SmsRegionConfig;
    multiFactorConfig?: MultiFactorConfig;
    recaptchaConfig?: RecaptchaConfig;
    passwordPolicyConfig?: PasswordPolicyConfig;
    emailPrivacyConfig?: EmailPrivacyConfig;
    mobileLinksConfig?: MobileLinksConfig;
}
/** Configuration results are plain JSON objects, like user records in this package. */
export interface ProjectConfig extends UpdateProjectConfigRequest {}
export interface UpdateTenantRequest
    extends Omit<UpdateProjectConfigRequest, 'mobileLinksConfig'> {
    displayName?: string;
    emailSignInConfig?: EmailSignInProviderConfig;
    anonymousSignInEnabled?: boolean;
    testPhoneNumbers?: Record<string, string> | null;
}
export type CreateTenantRequest = UpdateTenantRequest;
export interface Tenant extends UpdateTenantRequest {
    tenantId: string;
}
export interface ListTenantsResult {
    tenants: Tenant[];
    pageToken?: string;
}

/** Internal operation description; transport details belong to the endpoint layer. */
export interface AuthConfigOperation {
    resource: 'provider' | 'project' | 'tenant';
    action: 'create' | 'get' | 'update' | 'delete' | 'list';
    id?: string;
    type?: 'oidc' | 'saml';
    properties?: object;
    maxResults?: number;
    pageToken?: string;
}
export type AuthConfigExecutor = <T>(
    operation: AuthConfigOperation
) => Promise<AuthConfigResult<T>>;
