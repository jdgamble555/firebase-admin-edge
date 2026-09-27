import { FirebaseEdgeError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';

export interface FirestoreOpenTelemetryOptions {
    tracerProvider?: import('./firestore-telemetry.js').FirestoreTracerProvider;
}
export interface Settings {
    openTelemetry?: FirestoreOpenTelemetryOptions;
    projectId?: string;
    databaseId?: string;
    credentials?: { client_email: string; private_key: string };
    host?: string;
    port?: number;
    alwaysUseImplicitOrderBy?: boolean;
    ssl?: boolean;
    preferRest?: boolean;
    ignoreUndefinedProperties?: boolean;
    useBigInt?: boolean;
}

/** @internal Validate configuration before mutating the Firestore instance. */
export function validateSettings(settings: Settings): void {
    if (!settings || typeof settings !== 'object' || Array.isArray(settings))
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Expected Firestore settings.'
        });
    if (
        settings.openTelemetry !== undefined &&
        (!settings.openTelemetry ||
            typeof settings.openTelemetry !== 'object' ||
            Array.isArray(settings.openTelemetry) ||
            (settings.openTelemetry.tracerProvider !== undefined &&
                typeof settings.openTelemetry.tracerProvider?.getTracer !==
                    'function'))
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Expected an OpenTelemetry tracer provider.'
        });
    const allowed = [
        'projectId',
        'databaseId',
        'credentials',
        'host',
        'openTelemetry',
        'port',
        'alwaysUseImplicitOrderBy',
        'ssl',
        'preferRest',
        'ignoreUndefinedProperties',
        'useBigInt'
    ];
    for (const key of Object.keys(settings))
        if (!allowed.includes(key))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: `Unsupported edge Firestore setting: ${key}.`
            });
    for (const id of [settings.projectId, settings.databaseId])
        if (
            id !== undefined &&
            (typeof id !== 'string' || !id || id.includes('/'))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid project or database ID.'
            });
    for (const value of [
        settings.ssl,
        settings.alwaysUseImplicitOrderBy,
        settings.preferRest,
        settings.ignoreUndefinedProperties,
        settings.useBigInt
    ])
        if (value !== undefined && typeof value !== 'boolean')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a boolean setting.'
            });
    if (
        settings.port !== undefined &&
        (!Number.isInteger(settings.port) ||
            settings.port < 1 ||
            settings.port > 65535)
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Expected a port between 1 and 65535.'
        });
    if (settings.preferRest === false)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Edge Firestore requires REST transport.'
        });
    if (
        settings.credentials !== undefined &&
        (!settings.credentials ||
            typeof settings.credentials.client_email !== 'string' ||
            !settings.credentials.client_email ||
            typeof settings.credentials.private_key !== 'string' ||
            !settings.credentials.private_key)
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Expected service account credentials.'
        });
}
