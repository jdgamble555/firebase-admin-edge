/** Structured Firestore errors, using the same FirebaseEdgeError class as Auth. */
export const FirestoreErrorInfo = {
    INVALID_ARGUMENT: {
        code: 'firestore/invalid-argument',
        message: 'Invalid Firestore argument.'
    },
    FAILED_PRECONDITION: {
        code: 'firestore/failed-precondition',
        message: 'The Firestore operation cannot run in its current state.'
    },
    INVALID_RESPONSE: {
        code: 'firestore/internal',
        message: 'Firestore returned an invalid response.'
    },
    UNAUTHENTICATED: {
        code: 'firestore/unauthenticated',
        message: 'No service account access token returned.'
    },
    UNKNOWN: {
        code: 'firestore/unknown',
        message: 'Firestore request failed.'
    }
} as const;
