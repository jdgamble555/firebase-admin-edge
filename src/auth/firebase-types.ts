export type FirebaseRestError = {
    error: {
        code: number;
        message: string;
        errors?: {
            message: string;
            domain: string;
            reason: string;
        }[];
    };
};

export type FirebaseConfig = {
    apiKey: string;
    authDomain: string;
    projectId: string;
    storageBucket?: string;
    messagingSenderId?: string;
    appId?: string;
    measurementId?: string;
};

export type FirebaseCreateAuthUriResponse = {
    authUri: string;
    registered?: boolean;
    providerId?: string;
    allProviders?: string[];
    signinMethods?: string[];
    sessionId?: string;
};

export type FirebaseIdpSignInResponse = {
    idToken?: string;
    refreshToken?: string;
    expiresIn?: string;
    localId?: string;

    providerId?: string;
    federatedId?: string;
    email?: string | null;
    emailVerified?: boolean;
    rawUserInfo?: string;

    oauthIdToken?: string;
    oauthAccessToken?: string;
    oauthTokenSecret?: string;

    needConfirmation?: boolean;
    verifiedProvider?: string[];
};

export type GoogleTokenResponse = {
    access_token: string;
    expires_in: number;
    refresh_token?: string;
    scope: string;
    token_type: 'Bearer';
    id_token: string;
};

export type FirebaseRefreshTokenResponse = {
    access_token: string;
    expires_in: string;
    token_type: 'Bearer';
    refresh_token: string;
    id_token: string;
    user_id: string;
    project_id: string;
};

export type FirebaseIdTokenPayload = {
    iss: string;
    aud: string;
    auth_time: number;
    user_id: string;
    sub: string;
    iat: number;
    exp: number;
    email?: string;
    email_verified?: boolean;
    firebase: {
        identities: {
            email?: string[];
            'google.com'?: string[];
            [provider: string]: string[] | undefined;
        };
        sign_in_provider: string;
        tenant?: string;
    };
    uid?: string;
    name?: string;
    picture?: string;
};

export interface UserMetadata {
    creationTime: string | null;
    lastSignInTime: string | null;
    lastRefreshTime?: string | null;
}

export interface ServiceAccount {
    type: 'service_account';
    project_id: string;
    private_key_id: string;
    private_key: string;
    client_email: string;
    client_id: string;
    auth_uri: string;
    token_uri: string;
    auth_provider_x509_cert_url: string;
    client_x509_cert_url: string;
    universe_domain?: string;
}

export interface AccountsQueryResponse {
    recordsCount: string;
    userInfo: UserInfo[];
}

export interface UserInfo {
    localId: string;
    email?: string;
    displayName?: string;
    photoUrl?: string;
    emailVerified?: boolean;
    providerUserInfo?: ProviderUserInfo[];
    validSince?: string;
    lastLoginAt?: string;
    createdAt?: string;
    customAttributes?: string;
    emailLinkSignin?: boolean;
    initialEmail?: string;
    lastRefreshAt?: string;
    disabled?: boolean;
}

export interface ProviderUserInfo {
    providerId?: string;
    rawId?: string;
    email?: string;
    displayName?: string;
    photoUrl?: string;
    federatedId?: string;
    phoneNumber?: string;
}

export type FirebaseUpdateAccountResponse = {
    localId: string;
    email?: string;
    displayName?: string;
    photoUrl?: string;
    passwordHash?: string;
    providerUserInfo?: Array<{
        providerId: string;
        federatedId: string;
        displayName?: string;
        photoUrl?: string;
    }>;
    idToken?: string;
    refreshToken?: string;
    expiresIn?: string;
    emailVerified?: boolean;
};
