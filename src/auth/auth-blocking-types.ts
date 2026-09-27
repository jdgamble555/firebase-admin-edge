/** Raw user information carried by an Auth blocking-event JWT. */
export interface DecodedAuthBlockingUserRecord {
    uid: string;
    display_name?: string;
    email?: string;
    email_verified?: boolean;
    photo_url?: string;
    phone_number?: string;
    disabled?: boolean;
    tenant_id?: string;
    custom_claims?: Record<string, unknown>;
    metadata?: { creation_time?: number; last_sign_in_time?: number };
    [key: string]: unknown;
}

/** Verified blocking-event payload, not an ID token or a parsed Cloud Functions event. */
export interface DecodedAuthBlockingToken {
    aud: string;
    iss: string;
    iat: number;
    exp: number;
    /** Email/SMS events may have no user subject. */
    sub?: string;
    uid?: string;
    event_id: string;
    event_type: string;
    tenant_id?: string;
    user_record?: DecodedAuthBlockingUserRecord;
    ip_address?: string;
    user_agent?: string;
    locale?: string;
    sign_in_method?: string;
    raw_user_info?: string;
    sign_in_attributes?: Record<string, unknown>;
    oauth_id_token?: string;
    oauth_access_token?: string;
    oauth_refresh_token?: string;
    oauth_token_secret?: string;
    oauth_expires_in?: number;
    [key: string]: unknown;
}
