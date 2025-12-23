import type { FirebaseRestError } from './firebase-types.js';
import { FirebaseEdgeError, FirebaseEndpointErrorInfo } from './errors.js';

/**
 * Maps Firebase REST API errors to structured FirebaseEdgeError instances.
 * This function analyzes the Firebase error codes and HTTP status codes to determine
 * the most appropriate structured error type.
 *
 * Firebase errors come with specific error codes in the message field (e.g., USER_NOT_FOUND)
 * and additional details in the errors array with reason codes.
 *
 * @param firebaseError - The error object from Firebase REST API
 * @returns A structured FirebaseEdgeError instance
 */
export function mapFirebaseError(
    firebaseError: FirebaseRestError['error']
): FirebaseEdgeError {
    const { code, message, errors } = firebaseError;

    // First, check for specific Firebase error codes in the message field
    const firebaseErrorCode = message?.toUpperCase?.() || '';
    const reasonCode = errors?.[0]?.reason?.toUpperCase?.() || '';

    // Map specific Firebase error codes to structured errors (check if message contains the error code)
    if (firebaseErrorCode.includes('INVALID_CUSTOM_TOKEN')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_INVALID_CUSTOM_TOKEN
        );
    }
    if (
        firebaseErrorCode.includes('INVALID_REFRESH_TOKEN') ||
        firebaseErrorCode.includes('INVALID_GRANT')
    ) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_INVALID_REFRESH_TOKEN
        );
    }
    if (
        firebaseErrorCode.includes('TOKEN_EXPIRED') ||
        firebaseErrorCode.includes('CREDENTIAL_TOO_OLD_LOGIN_AGAIN')
    ) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_TOKEN_EXPIRED
        );
    }
    if (firebaseErrorCode.includes('INVALID_ID_TOKEN')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ID_TOKEN
        );
    }
    if (firebaseErrorCode.includes('INVALID_CREDENTIAL')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_INVALID_CREDENTIAL
        );
    }

    // User Management Errors
    if (
        firebaseErrorCode.includes('USER_NOT_FOUND') ||
        firebaseErrorCode.includes('EMAIL_NOT_FOUND')
    ) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND
        );
    }
    if (firebaseErrorCode.includes('USER_DISABLED')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_USER_DISABLED
        );
    }

    // Permission & Access Errors
    if (firebaseErrorCode.includes('PERMISSION_DENIED')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_PERMISSION_DENIED
        );
    }
    if (firebaseErrorCode.includes('INSUFFICIENT_PERMISSION')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_INSUFFICIENT_PERMISSION
        );
    }

    // Rate Limiting & Quota Errors
    if (firebaseErrorCode.includes('TOO_MANY_ATTEMPTS_TRY_LATER')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_TOO_MANY_REQUESTS
        );
    }
    if (firebaseErrorCode.includes('QUOTA_EXCEEDED')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_QUOTA_EXCEEDED
        );
    }

    // Provider & Configuration Errors
    if (firebaseErrorCode.includes('OPERATION_NOT_ALLOWED')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_PROVIDER_NOT_ENABLED
        );
    }
    if (firebaseErrorCode.includes('INVALID_IDP_RESPONSE')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_INVALID_PROVIDER_ID
        );
    }

    // Project & API Key Errors
    if (
        firebaseErrorCode.includes('API KEY NOT VALID') ||
        firebaseErrorCode.includes('INVALID_API_KEY')
    ) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_INVALID_API_KEY
        );
    }

    // Validation Errors
    if (
        firebaseErrorCode.includes('INVALID_EMAIL') ||
        firebaseErrorCode.includes('WEAK_PASSWORD') ||
        firebaseErrorCode.includes('EMAIL_EXISTS') ||
        firebaseErrorCode.includes('INVALID_PASSWORD') ||
        firebaseErrorCode.includes('MISSING_LOCAL_ID') ||
        firebaseErrorCode.includes('MISSING_EMAIL') ||
        firebaseErrorCode.includes('MISSING_PASSWORD') ||
        firebaseErrorCode.includes('MISSING_ID_TOKEN') ||
        firebaseErrorCode.includes('MISSING_OOB_CODE') ||
        firebaseErrorCode.includes('MISSING_SESSION_INFO') ||
        firebaseErrorCode.includes('MISSING_PHONE_NUMBER') ||
        firebaseErrorCode.includes('MISSING_CODE') ||
        firebaseErrorCode.includes('MISSING_REQ_TYPE') ||
        firebaseErrorCode.includes('MISSING_PROVIDER_ID') ||
        firebaseErrorCode.includes('MISSING_CONTINUE_URI') ||
        firebaseErrorCode.includes('MISSING_REFRESH_TOKEN') ||
        firebaseErrorCode.includes('INVALID_GRANT_TYPE')
    ) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT
        );
    }

    // Check reason codes if main message didn't match
    if (reasonCode.includes('INVALID')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT
        );
    }
    if (reasonCode.includes('FORBIDDEN')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_FORBIDDEN
        );
    }
    if (reasonCode.includes('NOTFOUND') || reasonCode.includes('NOT_FOUND')) {
        return new FirebaseEdgeError(
            FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND
        );
    }

    // Fallback to HTTP status code mapping if no specific Firebase error code matched
    switch (code) {
        case 400:
            return new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_INVALID_ARGUMENT
            );
        case 401:
            return new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_UNAUTHORIZED
            );
        case 403:
            return new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_FORBIDDEN
            );
        case 404:
            return new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_USER_NOT_FOUND
            );
        case 429:
            return new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_TOO_MANY_REQUESTS
            );
        case 500:
            return new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_INTERNAL_ERROR
            );
        case 502:
            return new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_BAD_GATEWAY
            );
        case 503:
            return new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_SERVICE_UNAVAILABLE
            );
        case 504:
            return new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_TIMEOUT
            );
        default:
            return new FirebaseEdgeError(
                FirebaseEndpointErrorInfo.ENDPOINT_UNKNOWN_ERROR,
                {
                    cause: new Error(message),
                    context: {
                        firebaseCode: code,
                        firebaseMessage: message,
                        firebaseErrors: errors
                    }
                }
            );
    }
}
