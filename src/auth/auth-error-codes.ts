export const FirebaseAdminAuthErrorInfo = {
    // User Management Errors
    ADMIN_USER_NOT_FOUND: {
        message: 'No user record found for the provided UID.',
        code: 'auth/admin-user-not-found'
    },
    ADMIN_USER_DISABLED: {
        message: 'The user account has been disabled by an administrator.',
        code: 'auth/admin-user-disabled'
    },
    ADMIN_INVALID_UID: {
        message: 'The provided UID is invalid or malformed.',
        code: 'auth/admin-invalid-uid'
    },
    ADMIN_UID_TOO_LONG: {
        message: 'The UID must not be longer than 128 characters.',
        code: 'auth/admin-uid-too-long'
    },
    ADMIN_USER_LOOKUP_FAILED: {
        message: 'Failed to retrieve user information from Firebase Admin.',
        code: 'auth/admin-user-lookup-failed'
    },

    // Service Account and Token Management
    ADMIN_SERVICE_ACCOUNT_TOKEN_FAILED: {
        message:
            'Failed to obtain service account access token for admin operations.',
        code: 'auth/admin-service-account-token-failed'
    },
    ADMIN_NO_TOKEN_RETURNED: {
        message:
            'No access token was returned from service account authentication.',
        code: 'auth/admin-no-token-returned'
    },
    ADMIN_INVALID_SERVICE_ACCOUNT: {
        message:
            'The service account configuration is invalid for admin operations.',
        code: 'auth/admin-invalid-service-account'
    },
    ADMIN_SERVICE_ACCOUNT_KEY_MISSING: {
        message: 'Service account key file is missing or invalid.',
        code: 'auth/admin-service-account-key-missing'
    },

    // ID Token Verification Errors
    ADMIN_ID_TOKEN_VERIFY_FAILED: {
        message: 'Failed to verify the Firebase ID token using admin SDK.',
        code: 'auth/admin-id-token-verify-failed'
    },
    ADMIN_ID_TOKEN_DECODE_FAILED: {
        message: 'Failed to decode the Firebase ID token payload.',
        code: 'auth/admin-id-token-decode-failed'
    },
    ADMIN_ID_TOKEN_EXPIRED: {
        message: 'The Firebase ID token has expired.',
        code: 'auth/admin-id-token-expired'
    },
    ADMIN_ID_TOKEN_REVOKED: {
        message: 'The Firebase ID token has been revoked.',
        code: 'auth/admin-id-token-revoked'
    },
    ADMIN_ID_TOKEN_INVALID: {
        message: 'The provided Firebase ID token is invalid.',
        code: 'auth/admin-id-token-invalid'
    },

    // Session Cookie Management
    ADMIN_SESSION_COOKIE_CREATE_FAILED: {
        message: 'Failed to create Firebase session cookie using admin SDK.',
        code: 'auth/admin-session-cookie-create-failed'
    },
    ADMIN_SESSION_COOKIE_VERIFY_FAILED: {
        message: 'Failed to verify Firebase session cookie using admin SDK.',
        code: 'auth/admin-session-cookie-verify-failed'
    },
    ADMIN_SESSION_COOKIE_EXPIRED: {
        message: 'The Firebase session cookie has expired.',
        code: 'auth/admin-session-cookie-expired'
    },
    ADMIN_SESSION_COOKIE_REVOKED: {
        message: 'The Firebase session cookie has been revoked.',
        code: 'auth/admin-session-cookie-revoked'
    },
    ADMIN_SESSION_COOKIE_INVALID: {
        message: 'The provided session cookie is invalid.',
        code: 'auth/admin-session-cookie-invalid'
    },
    ADMIN_SESSION_COOKIE_DURATION_INVALID: {
        message:
            'Session cookie duration must be between 5 minutes and 2 weeks.',
        code: 'auth/admin-session-cookie-duration-invalid'
    },

    // Custom Token Management
    ADMIN_CUSTOM_TOKEN_CREATE_FAILED: {
        message: 'Failed to create custom JWT token using admin SDK.',
        code: 'auth/admin-custom-token-create-failed'
    },
    ADMIN_CUSTOM_TOKEN_NO_DATA: {
        message: 'No custom token data was returned from creation process.',
        code: 'auth/admin-custom-token-no-data'
    },
    ADMIN_CUSTOM_TOKEN_INVALID_CLAIMS: {
        message: 'Invalid custom claims provided for admin token creation.',
        code: 'auth/admin-custom-token-invalid-claims'
    },
    ADMIN_CUSTOM_TOKEN_CLAIMS_TOO_LARGE: {
        message: 'Custom claims payload exceeds the maximum allowed size.',
        code: 'auth/admin-custom-token-claims-too-large'
    },

    // Token Revocation and Validation
    ADMIN_TOKEN_REVOCATION_CHECK_FAILED: {
        message: 'Failed to check if token has been revoked.',
        code: 'auth/admin-token-revocation-check-failed'
    },
    ADMIN_REVOKE_TOKENS_FAILED: {
        message: 'Failed to revoke refresh tokens for the user.',
        code: 'auth/admin-revoke-tokens-failed'
    },
    ADMIN_TOKENS_VALID_AFTER_CHECK_FAILED: {
        message:
            'Failed to validate token against user tokens valid after time.',
        code: 'auth/admin-tokens-valid-after-check-failed'
    },
    ADMIN_USER_RECORD_NOT_FOUND: {
        message: 'No user record found during token revocation check.',
        code: 'auth/admin-user-record-not-found'
    },

    // Firebase REST API Admin Errors
    ADMIN_API_REQUEST_FAILED: {
        message: 'Firebase Admin API request failed.',
        code: 'auth/admin-api-request-failed'
    },
    ADMIN_API_QUOTA_EXCEEDED: {
        message: 'Firebase Admin API quota exceeded.',
        code: 'auth/admin-api-quota-exceeded'
    },
    ADMIN_API_PERMISSION_DENIED: {
        message: 'Permission denied for Firebase Admin API operation.',
        code: 'auth/admin-api-permission-denied'
    },
    ADMIN_API_NETWORK_ERROR: {
        message: 'Network error occurred during Firebase Admin API request.',
        code: 'auth/admin-api-network-error'
    },
    ADMIN_API_INVALID_ARGUMENT: {
        message: 'Invalid argument provided to Firebase Admin API.',
        code: 'auth/admin-api-invalid-argument'
    },

    // Project and Configuration Errors
    ADMIN_PROJECT_NOT_FOUND: {
        message: 'Firebase project not found or not accessible.',
        code: 'auth/admin-project-not-found'
    },
    ADMIN_PROJECT_ID_INVALID: {
        message: 'The provided Firebase project ID is invalid.',
        code: 'auth/admin-project-id-invalid'
    },
    ADMIN_INSUFFICIENT_PERMISSION: {
        message: 'Insufficient permissions for admin operation.',
        code: 'auth/admin-insufficient-permission'
    },

    // Generic Admin Errors
    ADMIN_OPERATION_FAILED: {
        message: 'Firebase Admin operation failed.',
        code: 'auth/admin-operation-failed'
    },
    ADMIN_INTERNAL_ERROR: {
        message: 'An internal error occurred in Firebase Admin SDK.',
        code: 'auth/admin-internal-error'
    },
    ADMIN_UNKNOWN_ERROR: {
        message: 'An unknown error occurred during admin operation.',
        code: 'auth/admin-unknown-error'
    },

    // Account Import/Export Errors
    ADMIN_USER_IMPORT_FAILED: {
        message: 'Failed to import user accounts.',
        code: 'auth/admin-user-import-failed'
    },
    ADMIN_USER_EXPORT_FAILED: {
        message: 'Failed to export user accounts.',
        code: 'auth/admin-user-export-failed'
    },

    // Tenant Management (Multi-tenancy)
    ADMIN_TENANT_NOT_FOUND: {
        message: 'The specified tenant was not found.',
        code: 'auth/admin-tenant-not-found'
    },
    ADMIN_TENANT_ID_INVALID: {
        message: 'The provided tenant ID is invalid.',
        code: 'auth/admin-tenant-id-invalid'
    },

    // Email and Phone Verification
    ADMIN_EMAIL_VERIFICATION_FAILED: {
        message: 'Failed to send email verification.',
        code: 'auth/admin-email-verification-failed'
    },
    ADMIN_PHONE_VERIFICATION_FAILED: {
        message: 'Failed to send phone verification.',
        code: 'auth/admin-phone-verification-failed'
    },

    // Provider Management
    ADMIN_PROVIDER_CONFIG_INVALID: {
        message: 'Invalid provider configuration for admin operations.',
        code: 'auth/admin-provider-config-invalid'
    },
    ADMIN_PROVIDER_NOT_ENABLED: {
        message: 'The authentication provider is not enabled.',
        code: 'auth/admin-provider-not-enabled'
    }
};

export const FirebaseAuthErrorInfo = {
    // Authentication Token Errors
    AUTH_TOKEN_EXPIRED: {
        message: 'The Firebase Auth token has expired.',
        code: 'auth/token-expired'
    },
    AUTH_INVALID_TOKEN: {
        message: 'The Firebase Auth token is invalid.',
        code: 'auth/invalid-token'
    },
    AUTH_TOKEN_REVOKED: {
        message: 'The Firebase Auth token has been revoked.',
        code: 'auth/token-revoked'
    },
    AUTH_TOKEN_NOT_FOUND: {
        message: 'No Firebase Auth token provided.',
        code: 'auth/token-not-found'
    },

    // User Management Errors
    AUTH_USER_NOT_FOUND: {
        message: 'No user record found for the provided identifier.',
        code: 'auth/user-not-found'
    },
    AUTH_USER_DISABLED: {
        message: 'The user account has been disabled.',
        code: 'auth/user-disabled'
    },
    AUTH_USER_RECORD_NOT_FOUND: {
        message: 'No user record found.',
        code: 'auth/user-record-not-found'
    },
    AUTH_INVALID_USER_UID: {
        message: 'The provided user UID is invalid.',
        code: 'auth/invalid-uid'
    },

    // ID Token Verification Errors
    AUTH_ID_TOKEN_EXPIRED: {
        message: 'The Firebase ID token has expired.',
        code: 'auth/id-token-expired'
    },
    AUTH_ID_TOKEN_REVOKED: {
        message: 'The Firebase ID token has been revoked.',
        code: 'auth/id-token-revoked'
    },
    AUTH_INVALID_ID_TOKEN: {
        message: 'The Firebase ID token is invalid.',
        code: 'auth/invalid-id-token'
    },
    AUTH_ID_TOKEN_VERIFY_FAILED: {
        message: 'Failed to verify Firebase ID token.',
        code: 'auth/id-token-verify-failed'
    },
    AUTH_ID_TOKEN_DECODE_FAILED: {
        message: 'Failed to decode Firebase ID token.',
        code: 'auth/id-token-decode-failed'
    },

    // Session Cookie Errors
    AUTH_SESSION_COOKIE_EXPIRED: {
        message: 'The Firebase session cookie has expired.',
        code: 'auth/session-cookie-expired'
    },
    AUTH_SESSION_COOKIE_REVOKED: {
        message: 'The Firebase session cookie has been revoked.',
        code: 'auth/session-cookie-revoked'
    },
    AUTH_INVALID_SESSION_COOKIE: {
        message: 'The Firebase session cookie is invalid.',
        code: 'auth/invalid-session-cookie'
    },
    AUTH_SESSION_COOKIE_VERIFY_FAILED: {
        message: 'Failed to verify Firebase session cookie.',
        code: 'auth/session-cookie-verify-failed'
    },
    AUTH_SESSION_COOKIE_CREATE_FAILED: {
        message: 'Failed to create Firebase session cookie.',
        code: 'auth/session-cookie-create-failed'
    },

    // Custom Token Errors
    AUTH_INVALID_CUSTOM_TOKEN: {
        message: 'The custom token format is invalid.',
        code: 'auth/invalid-custom-token'
    },
    AUTH_CUSTOM_TOKEN_MISMATCH: {
        message: 'The custom token corresponds to a different project.',
        code: 'auth/custom-token-mismatch'
    },
    AUTH_CUSTOM_TOKEN_SIGN_FAILED: {
        message: 'Failed to sign custom token.',
        code: 'auth/custom-token-sign-failed'
    },
    AUTH_INVALID_DEVELOPER_CLAIMS: {
        message: 'Invalid developer claims provided for custom token.',
        code: 'auth/invalid-developer-claims'
    },

    // Service Account Errors
    AUTH_INVALID_SERVICE_ACCOUNT: {
        message: 'The service account configuration is invalid.',
        code: 'auth/invalid-service-account'
    },
    AUTH_SERVICE_ACCOUNT_TOKEN_FAILED: {
        message: 'Failed to obtain service account access token.',
        code: 'auth/service-account-token-failed'
    },
    AUTH_MISSING_SERVICE_ACCOUNT: {
        message: 'Service account configuration is missing.',
        code: 'auth/missing-service-account'
    },

    // Firebase REST API Errors
    AUTH_API_REQUEST_FAILED: {
        message: 'Firebase Auth API request failed.',
        code: 'auth/api-request-failed'
    },
    AUTH_NETWORK_ERROR: {
        message: 'Network error occurred during Firebase Auth request.',
        code: 'auth/network-error'
    },
    AUTH_QUOTA_EXCEEDED: {
        message: 'Firebase Auth quota exceeded.',
        code: 'auth/quota-exceeded'
    },
    AUTH_UNAUTHORIZED: {
        message: 'Unauthorized to perform Firebase Auth operation.',
        code: 'auth/unauthorized'
    },

    // Provider Sign-In Errors
    AUTH_PROVIDER_SIGN_IN_FAILED: {
        message: 'Failed to sign in with identity provider.',
        code: 'auth/provider-sign-in-failed'
    },
    AUTH_PROVIDER_LINK_FAILED: {
        message: 'Failed to link identity provider credential.',
        code: 'auth/provider-link-failed'
    },
    AUTH_PROVIDER_UNLINK_FAILED: {
        message: 'Failed to unlink identity provider.',
        code: 'auth/provider-unlink-failed'
    },
    AUTH_INVALID_PROVIDER_ID: {
        message: 'The provider ID is not supported.',
        code: 'auth/invalid-provider-id'
    },
    AUTH_PROVIDER_DATA_MISSING: {
        message: 'Provider sign-in data is missing or invalid.',
        code: 'auth/provider-data-missing'
    },

    // Account Linking Errors
    AUTH_EMAIL_ALREADY_EXISTS: {
        message: 'The email address is already in use by another account.',
        code: 'auth/email-already-exists'
    },
    AUTH_PHONE_NUMBER_ALREADY_EXISTS: {
        message: 'The phone number is already in use by another account.',
        code: 'auth/phone-number-already-exists'
    },
    AUTH_UID_ALREADY_EXISTS: {
        message: 'The user with the provided UID already exists.',
        code: 'auth/uid-already-exists'
    },

    // Refresh Token Errors
    AUTH_REFRESH_TOKEN_EXPIRED: {
        message: 'The refresh token has expired.',
        code: 'auth/refresh-token-expired'
    },
    AUTH_INVALID_REFRESH_TOKEN: {
        message: 'The refresh token is invalid.',
        code: 'auth/invalid-refresh-token'
    },
    AUTH_REFRESH_TOKEN_FAILED: {
        message: 'Failed to refresh Firebase ID token.',
        code: 'auth/refresh-token-failed'
    },

    // Configuration Errors
    AUTH_INVALID_API_KEY: {
        message: 'The Firebase API key is invalid.',
        code: 'auth/invalid-api-key'
    },
    AUTH_INVALID_PROJECT_ID: {
        message: 'The Firebase project ID is invalid.',
        code: 'auth/invalid-project-id'
    },
    AUTH_PROJECT_NOT_FOUND: {
        message: 'The Firebase project was not found.',
        code: 'auth/project-not-found'
    },

    // Multi-factor Authentication Errors
    AUTH_MFA_REQUIRED: {
        message: 'Multi-factor authentication is required.',
        code: 'auth/multi-factor-auth-required'
    },
    AUTH_INVALID_MFA_SESSION: {
        message: 'The multi-factor authentication session is invalid.',
        code: 'auth/invalid-multi-factor-session'
    },

    // Tenant Management Errors
    AUTH_INVALID_TENANT_ID: {
        message: 'The tenant ID is invalid.',
        code: 'auth/invalid-tenant-id'
    },
    AUTH_TENANT_NOT_FOUND: {
        message: 'The tenant was not found.',
        code: 'auth/tenant-not-found'
    },

    // Claims and Permissions Errors
    AUTH_INSUFFICIENT_PERMISSION: {
        message: 'Insufficient permission to perform the operation.',
        code: 'auth/insufficient-permission'
    },
    AUTH_INVALID_CLAIMS: {
        message: 'The custom claims object is invalid.',
        code: 'auth/invalid-claims'
    },
    AUTH_CLAIMS_TOO_LARGE: {
        message: 'The custom claims exceed the maximum allowed size.',
        code: 'auth/claims-too-large'
    },

    // Authentication State Errors
    AUTH_USER_MISMATCH: {
        message: 'The user does not match the authenticated user.',
        code: 'auth/user-mismatch'
    },
    AUTH_OPERATION_NOT_ALLOWED: {
        message: 'The authentication operation is not allowed.',
        code: 'auth/operation-not-allowed'
    },
    AUTH_ADMIN_RESTRICTED_OPERATION: {
        message: 'This operation is restricted to administrators only.',
        code: 'auth/admin-restricted-operation'
    },

    // Generic Firebase Auth Errors
    AUTH_INTERNAL_ERROR: {
        message: 'An internal error occurred in Firebase Auth.',
        code: 'auth/internal-error'
    },
    AUTH_UNKNOWN_ERROR: {
        message: 'An unknown error occurred in Firebase Auth.',
        code: 'auth/unknown-error'
    },
    AUTH_OPERATION_FAILED: {
        message: 'The Firebase Auth operation failed.',
        code: 'auth/operation-failed'
    }
};

export const JWTErrorInfo = {
    // JWT Verification Errors
    JWT_EXPIRED: {
        message: 'The JWT token has expired.',
        code: 'auth/jwt-expired'
    },
    JWT_INVALID_SIGNATURE: {
        message: 'JWT signature verification failed.',
        code: 'auth/jwt-invalid-signature'
    },
    JWT_CLAIM_VALIDATION_FAILED: {
        message: 'JWT claim validation failed.',
        code: 'auth/jwt-claim-validation-failed'
    },
    JWT_INVALID_TOKEN: {
        message: 'The JWT token is invalid or malformed.',
        code: 'auth/jwt-invalid-token'
    },
    JWT_NO_KID_FOUND: {
        message: 'Invalid JWT: no Key ID (KID) found in header.',
        code: 'auth/jwt-no-kid-found'
    },
    JWT_NO_MATCHING_KEY: {
        message: 'No matching public key found for the JWT Key ID.',
        code: 'auth/jwt-no-matching-key'
    },
    JWT_NO_PUBLIC_KEYS: {
        message: 'No public keys retrieved for JWT verification.',
        code: 'auth/jwt-no-public-keys'
    },
    JWT_NO_JWKS_RETRIEVED: {
        message: 'No JSON Web Key Set (JWKS) retrieved for verification.',
        code: 'auth/jwt-no-jwks-retrieved'
    },

    // JWT Signing Errors
    JWT_PRIVATE_KEY_IMPORT_FAILED: {
        message: 'Failed to import private key for JWT signing.',
        code: 'auth/jwt-private-key-import-failed'
    },
    JWT_SIGNING_FAILED: {
        message: 'Failed to sign JWT token.',
        code: 'auth/jwt-signing-failed'
    },
    JWT_JOSE_ERROR: {
        message: 'JOSE library error occurred during JWT operation.',
        code: 'auth/jwt-jose-error'
    },
    JWT_UNKNOWN_SIGNING_ERROR: {
        message: 'Unknown error occurred during JWT signing.',
        code: 'auth/jwt-unknown-signing-error'
    },
    JWT_UNKNOWN_VERIFICATION_ERROR: {
        message: 'Unknown error occurred during JWT verification.',
        code: 'auth/jwt-unknown-verification-error'
    },

    // Custom Token Specific Errors
    JWT_RESERVED_CLAIMS: {
        message: 'Reserved claims cannot be used in custom JWT tokens.',
        code: 'auth/jwt-reserved-claims'
    },
    JWT_INVALID_CUSTOM_CLAIMS: {
        message: 'Invalid custom claims provided for JWT token.',
        code: 'auth/jwt-invalid-custom-claims'
    },

    // Session Cookie Specific Errors
    JWT_INVALID_SESSION_COOKIE: {
        message: 'Invalid session cookie format or content.',
        code: 'auth/jwt-invalid-session-cookie'
    },
    JWT_SESSION_COOKIE_EXPIRED: {
        message: 'The session cookie has expired.',
        code: 'auth/jwt-session-cookie-expired'
    },

    // Key Management Errors
    JWT_KEY_CACHE_ERROR: {
        message: 'Error occurred while caching cryptographic keys.',
        code: 'auth/jwt-key-cache-error'
    },
    JWT_PUBLIC_KEY_FORMAT_ERROR: {
        message: 'Public key format is invalid or unsupported.',
        code: 'auth/jwt-public-key-format-error'
    },

    // Service Account Errors
    JWT_INVALID_SERVICE_ACCOUNT: {
        message: 'Invalid service account configuration for JWT operations.',
        code: 'auth/jwt-invalid-service-account'
    },
    JWT_MISSING_PRIVATE_KEY: {
        message: 'Private key is missing from service account configuration.',
        code: 'auth/jwt-missing-private-key'
    },
    JWT_MISSING_CLIENT_EMAIL: {
        message: 'Client email is missing from service account configuration.',
        code: 'auth/jwt-missing-client-email'
    },

    // Token Format Errors
    JWT_MALFORMED_HEADER: {
        message: 'JWT header is malformed or missing required fields.',
        code: 'auth/jwt-malformed-header'
    },
    JWT_MALFORMED_PAYLOAD: {
        message: 'JWT payload is malformed or missing required claims.',
        code: 'auth/jwt-malformed-payload'
    },
    JWT_INVALID_ALGORITHM: {
        message: 'JWT uses an unsupported or invalid algorithm.',
        code: 'auth/jwt-invalid-algorithm'
    },

    // Audience/Issuer Validation Errors
    JWT_INVALID_AUDIENCE: {
        message: 'JWT audience claim does not match expected value.',
        code: 'auth/jwt-invalid-audience'
    },
    JWT_INVALID_ISSUER: {
        message: 'JWT issuer claim does not match expected value.',
        code: 'auth/jwt-invalid-issuer'
    },
    JWT_INVALID_SUBJECT: {
        message: 'JWT subject claim is invalid or missing.',
        code: 'auth/jwt-invalid-subject'
    }
};

export const GitHubErrorInfo = {
    GITHUB_CODE_EXCHANGE_FAILED: {
        message:
            'Failed to exchange authorization code for GitHub access token.',
        code: 'auth/github-code-exchange-failed'
    },
    GITHUB_INCORRECT_CLIENT_CREDENTIALS: {
        message: 'The GitHub client credentials are incorrect.',
        code: 'auth/github-incorrect-client-credentials'
    },
    GITHUB_REDIRECT_URI_MISMATCH: {
        message:
            'The GitHub redirect URI does not match the one configured for the app.',
        code: 'auth/github-redirect-uri-mismatch'
    },
    GITHUB_BAD_VERIFICATION_CODE: {
        message: 'The GitHub verification code is incorrect or expired.',
        code: 'auth/github-bad-verification-code'
    },
    GITHUB_UNVERIFIED_USER_EMAIL: {
        message: 'The GitHub user email is unverified.',
        code: 'auth/github-unverified-user-email'
    },
    GITHUB_ACCESS_DENIED: {
        message: 'User denied the GitHub OAuth authorization request.',
        code: 'auth/github-access-denied'
    },
    GITHUB_UNSUPPORTED_GRANT_TYPE: {
        message: 'The GitHub OAuth grant type is not supported.',
        code: 'auth/github-unsupported-grant-type'
    },
    GITHUB_INVALID_CLIENT: {
        message: 'The GitHub OAuth client is invalid.',
        code: 'auth/github-invalid-client'
    },
    GITHUB_INVALID_REQUEST: {
        message:
            'The GitHub OAuth request is malformed or missing required parameters.',
        code: 'auth/github-invalid-request'
    },
    GITHUB_UNAUTHORIZED_CLIENT: {
        message:
            'The GitHub client is not authorized to request an access token.',
        code: 'auth/github-unauthorized-client'
    },
    GITHUB_INVALID_SCOPE: {
        message: 'The requested GitHub OAuth scope is invalid or unknown.',
        code: 'auth/github-invalid-scope'
    },
    GITHUB_SERVER_ERROR: {
        message: 'GitHub OAuth server encountered an error.',
        code: 'auth/github-server-error'
    },
    GITHUB_TEMPORARILY_UNAVAILABLE: {
        message: 'GitHub OAuth server is temporarily unavailable.',
        code: 'auth/github-temporarily-unavailable'
    },
    GITHUB_TOKEN_REQUEST_FAILED: {
        message: 'Failed to request token from GitHub OAuth endpoint.',
        code: 'auth/github-token-request-failed'
    }
};

export const GoogleErrorInfo = {
    GOOGLE_CODE_EXCHANGE_FAILED: {
        message: 'Failed to exchange authorization code for Google ID token.',
        code: 'auth/google-code-exchange-failed'
    },
    GOOGLE_INVALID_GRANT: {
        message:
            'The provided authorization grant is invalid, expired, revoked, or does not match the redirection URI.',
        code: 'auth/google-invalid-grant'
    },
    GOOGLE_INVALID_CLIENT: {
        message: 'The Google OAuth client credentials are invalid.',
        code: 'auth/google-invalid-client'
    },
    GOOGLE_INVALID_REQUEST: {
        message:
            'The Google OAuth request is malformed or missing required parameters.',
        code: 'auth/google-invalid-request'
    },
    GOOGLE_ACCESS_DENIED: {
        message: 'User denied the Google OAuth authorization request.',
        code: 'auth/google-access-denied'
    },
    GOOGLE_UNSUPPORTED_RESPONSE_TYPE: {
        message: 'The Google OAuth response type is not supported.',
        code: 'auth/google-unsupported-response-type'
    },
    GOOGLE_INVALID_SCOPE: {
        message: 'The requested Google OAuth scope is invalid or unknown.',
        code: 'auth/google-invalid-scope'
    },
    GOOGLE_SERVER_ERROR: {
        message: 'Google OAuth server encountered an error.',
        code: 'auth/google-server-error'
    },
    GOOGLE_TEMPORARILY_UNAVAILABLE: {
        message: 'Google OAuth server is temporarily unavailable.',
        code: 'auth/google-temporarily-unavailable'
    },
    JWT_SIGN_FAILED: {
        message: 'Failed to sign JWT for service account authentication.',
        code: 'auth/jwt-sign-failed'
    },
    JWT_DATA_MISSING: {
        message: 'No JWT data was returned from signing process.',
        code: 'auth/jwt-data-missing'
    },
    SERVICE_ACCOUNT_TOKEN_FAILED: {
        message: 'Failed to obtain service account access token.',
        code: 'auth/service-account-token-failed'
    },
    GOOGLE_TOKEN_REQUEST_FAILED: {
        message: 'Failed to request token from Google OAuth endpoint.',
        code: 'auth/google-token-request-failed'
    }
};

export const FirebaseEndpointErrorInfo = {
    // Authentication Errors
    ENDPOINT_INVALID_CREDENTIAL: {
        message: 'Invalid credentials provided to Firebase endpoint.',
        code: 'auth/endpoint-invalid-credential'
    },
    ENDPOINT_USER_NOT_FOUND: {
        message: 'No user found for the provided identifier.',
        code: 'auth/endpoint-user-not-found'
    },
    ENDPOINT_INVALID_ID_TOKEN: {
        message: 'The provided ID token is invalid or expired.',
        code: 'auth/endpoint-invalid-id-token'
    },
    ENDPOINT_INVALID_REFRESH_TOKEN: {
        message: 'The provided refresh token is invalid or expired.',
        code: 'auth/endpoint-invalid-refresh-token'
    },
    ENDPOINT_INVALID_CUSTOM_TOKEN: {
        message: 'The provided custom token is invalid or malformed.',
        code: 'auth/endpoint-invalid-custom-token'
    },
    ENDPOINT_TOKEN_EXPIRED: {
        message: 'The authentication token has expired.',
        code: 'auth/endpoint-token-expired'
    },
    ENDPOINT_USER_DISABLED: {
        message: 'The user account has been disabled.',
        code: 'auth/endpoint-user-disabled'
    },

    // Authorization Errors
    ENDPOINT_PERMISSION_DENIED: {
        message: 'Permission denied for this Firebase operation.',
        code: 'auth/endpoint-permission-denied'
    },
    ENDPOINT_INSUFFICIENT_PERMISSION: {
        message: 'Insufficient permission to access this Firebase resource.',
        code: 'auth/endpoint-insufficient-permission'
    },
    ENDPOINT_UNAUTHORIZED: {
        message: 'Request is not authorized to access Firebase endpoint.',
        code: 'auth/endpoint-unauthorized'
    },
    ENDPOINT_FORBIDDEN: {
        message: 'Access to Firebase endpoint is forbidden.',
        code: 'auth/endpoint-forbidden'
    },

    // Rate Limiting & Quota
    ENDPOINT_QUOTA_EXCEEDED: {
        message: 'Firebase API quota exceeded. Please try again later.',
        code: 'auth/endpoint-quota-exceeded'
    },
    ENDPOINT_TOO_MANY_REQUESTS: {
        message:
            'Too many requests to Firebase endpoint. Please try again later.',
        code: 'auth/endpoint-too-many-requests'
    },
    ENDPOINT_RATE_LIMITED: {
        message: 'Request rate limited by Firebase service.',
        code: 'auth/endpoint-rate-limited'
    },

    // Service & Network Errors
    ENDPOINT_SERVICE_UNAVAILABLE: {
        message: 'Firebase service is temporarily unavailable.',
        code: 'auth/endpoint-service-unavailable'
    },
    ENDPOINT_NETWORK_ERROR: {
        message: 'Network error occurred during Firebase API request.',
        code: 'auth/endpoint-network-error'
    },
    ENDPOINT_TIMEOUT: {
        message: 'Request to Firebase endpoint timed out.',
        code: 'auth/endpoint-timeout'
    },
    ENDPOINT_INTERNAL_ERROR: {
        message: 'Internal error occurred in Firebase service.',
        code: 'auth/endpoint-internal-error'
    },
    ENDPOINT_BAD_GATEWAY: {
        message: 'Bad gateway response from Firebase service.',
        code: 'auth/endpoint-bad-gateway'
    },

    // Parameter & Request Errors
    ENDPOINT_INVALID_ARGUMENT: {
        message: 'Invalid argument provided to Firebase endpoint.',
        code: 'auth/endpoint-invalid-argument'
    },
    ENDPOINT_MISSING_PARAMETER: {
        message: 'Required parameter is missing from Firebase request.',
        code: 'auth/endpoint-missing-parameter'
    },
    ENDPOINT_INVALID_REQUEST: {
        message: 'The request to Firebase endpoint is invalid or malformed.',
        code: 'auth/endpoint-invalid-request'
    },
    ENDPOINT_INVALID_PROJECT_ID: {
        message: 'The provided project ID is invalid.',
        code: 'auth/endpoint-invalid-project-id'
    },
    ENDPOINT_INVALID_API_KEY: {
        message: 'The provided API key is invalid.',
        code: 'auth/endpoint-invalid-api-key'
    },

    // Provider-Specific Errors
    ENDPOINT_INVALID_PROVIDER_ID: {
        message: 'The authentication provider ID is invalid.',
        code: 'auth/endpoint-invalid-provider-id'
    },
    ENDPOINT_PROVIDER_NOT_ENABLED: {
        message: 'The authentication provider is not enabled for this project.',
        code: 'auth/endpoint-provider-not-enabled'
    },
    ENDPOINT_INVALID_PROVIDER_TOKEN: {
        message: 'The provider token is invalid or expired.',
        code: 'auth/endpoint-invalid-provider-token'
    },

    // Session Cookie Errors
    ENDPOINT_INVALID_SESSION_COOKIE: {
        message: 'The provided session cookie is invalid.',
        code: 'auth/endpoint-invalid-session-cookie'
    },
    ENDPOINT_SESSION_COOKIE_EXPIRED: {
        message: 'The session cookie has expired.',
        code: 'auth/endpoint-session-cookie-expired'
    },
    ENDPOINT_INVALID_DURATION: {
        message: 'Invalid session duration specified.',
        code: 'auth/endpoint-invalid-duration'
    },

    // Key & Certificate Errors
    ENDPOINT_KEY_FETCH_FAILED: {
        message: 'Failed to fetch public keys from Firebase.',
        code: 'auth/endpoint-key-fetch-failed'
    },
    ENDPOINT_INVALID_KEY_FORMAT: {
        message: 'The public key format is invalid.',
        code: 'auth/endpoint-invalid-key-format'
    },
    ENDPOINT_CERTIFICATE_ERROR: {
        message: 'Error with Firebase certificate validation.',
        code: 'auth/endpoint-certificate-error'
    },

    // Generic Endpoint Errors
    ENDPOINT_OPERATION_FAILED: {
        message: 'Firebase endpoint operation failed.',
        code: 'auth/endpoint-operation-failed'
    },
    ENDPOINT_UNKNOWN_ERROR: {
        message: 'An unknown error occurred in Firebase endpoint.',
        code: 'auth/endpoint-unknown-error'
    },
    ENDPOINT_PARSE_ERROR: {
        message: 'Failed to parse Firebase API response.',
        code: 'auth/endpoint-parse-error'
    }
};
