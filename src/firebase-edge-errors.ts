export const FirebaseEdgeServerErrorInfo = {
    // Provider Configuration Errors
    EDGE_PROVIDER_NOT_CONFIGURED: {
        message: 'OAuth provider not configured for this edge server instance.',
        code: 'edge/provider-not-configured'
    },
    EDGE_GOOGLE_PROVIDER_NOT_CONFIGURED: {
        message: 'Google provider not configured.',
        code: 'edge/google-provider-not-configured'
    },
    EDGE_GITHUB_PROVIDER_NOT_CONFIGURED: {
        message: 'GitHub provider not configured.',
        code: 'edge/github-provider-not-configured'
    },

    // OAuth Flow Errors
    EDGE_NO_AUTHORIZATION_CODE: {
        message: 'No authorization code provided in OAuth callback.',
        code: 'edge/no-authorization-code'
    },
    EDGE_NO_PROVIDER_IN_STATE: {
        message: 'No provider specified in state.',
        code: 'edge/no-provider-in-state'
    },
    EDGE_INVALID_STATE_FORMAT: {
        message: 'OAuth state parameter has invalid format.',
        code: 'edge/invalid-state-format'
    },
    EDGE_NO_OAUTH_TOKEN: {
        message: 'No OAuth token obtained from provider.',
        code: 'edge/no-oauth-token'
    },
    EDGE_NO_EXCHANGE_DATA: {
        message: 'No exchange data returned from OAuth provider.',
        code: 'edge/no-exchange-data'
    },
    EDGE_NO_SIGN_IN_DATA: {
        message: 'No sign-in data obtained from authentication.',
        code: 'edge/no-sign-in-data'
    },

    EDGE_NO_USER_RECORD: {
        message: 'No user record found after sign-in.',
        code: 'edge/no-user-record'
    },

    // Token and Session Errors
    EDGE_NO_ID_TOKEN: {
        message: 'No ID token obtained from sign-in.',
        code: 'edge/no-id-token'
    },
    EDGE_NO_SESSION_COOKIE: {
        message: 'No session cookie returned from authentication.',
        code: 'edge/no-session-cookie'
    },
    EDGE_NO_CUSTOM_TOKEN_SIGNED: {
        message: 'No custom token signed for user.',
        code: 'edge/no-custom-token-signed'
    },
    EDGE_ACCOUNT_EXISTS_DIFFERENT_METHOD: {
        message: 'Account exists with a different sign-in method.',
        code: 'edge/account-exists-different-method'
    },
    EDGE_NO_EMAIL_FOR_AUTO_LINKING: {
        message: 'No email available for auto-linking accounts.',
        code: 'edge/no-email-for-auto-linking'
    },

    // Session Management Errors
    EDGE_SESSION_EXPIRED: {
        message: 'Edge server session has expired.',
        code: 'edge/session-expired'
    },
    EDGE_SESSION_INVALID: {
        message: 'Edge server session is invalid.',
        code: 'edge/session-invalid'
    },
    EDGE_SESSION_REVOKED: {
        message: 'Edge server session has been revoked.',
        code: 'edge/session-revoked'
    },

    // Configuration Errors
    EDGE_SERVICE_ACCOUNT_MISSING: {
        message: 'Service account configuration is required for edge server.',
        code: 'edge/service-account-missing'
    },
    EDGE_FIREBASE_CONFIG_MISSING: {
        message: 'Firebase configuration is required for edge server.',
        code: 'edge/firebase-config-missing'
    },
    EDGE_COOKIE_FUNCTIONS_MISSING: {
        message: 'Cookie management functions are required for edge server.',
        code: 'edge/cookie-functions-missing'
    },

    // Runtime Environment Errors
    EDGE_FETCH_NOT_AVAILABLE: {
        message: 'Fetch function not available in edge environment.',
        code: 'edge/fetch-not-available'
    },
    EDGE_ENVIRONMENT_NOT_SUPPORTED: {
        message: 'Current environment is not supported for edge server.',
        code: 'edge/environment-not-supported'
    },

    // Generic Edge Server Errors
    EDGE_SERVER_INITIALIZATION_FAILED: {
        message: 'Firebase edge server initialization failed.',
        code: 'edge/server-initialization-failed'
    },
    EDGE_OPERATION_FAILED: {
        message: 'Edge server operation failed.',
        code: 'edge/operation-failed'
    },
    EDGE_UNKNOWN_ERROR: {
        message: 'An unknown error occurred in Firebase edge server.',
        code: 'edge/unknown-error'
    }
};
