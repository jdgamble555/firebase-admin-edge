import {
    FirebaseAdminAuthErrorInfo,
    FirebaseEdgeError,
    ensureError
} from './errors.js';

export interface ActionCodeSettings {
    url: string;
    handleCodeInApp?: boolean;
    iOS?: { bundleId: string };
    android?: {
        packageName: string;
        installApp?: boolean;
        minimumVersion?: string;
    };
    /** @deprecated Use linkDomain instead. */
    dynamicLinkDomain?: string;
    linkDomain?: string;
}

export type EmailActionType =
    | 'PASSWORD_RESET'
    | 'VERIFY_EMAIL'
    | 'VERIFY_AND_CHANGE_EMAIL'
    | 'EMAIL_SIGNIN';
export interface EmailActionRequest {
    requestType: EmailActionType;
    email: string;
    newEmail?: string;
    returnOobLink: true;
    continueUrl?: string;
    canHandleCodeInApp?: boolean;
    iOSBundleId?: string;
    androidPackageName?: string;
    androidInstallApp?: boolean;
    androidMinimumVersion?: string;
    dynamicLinkDomain?: string;
    linkDomain?: string;
}

/** Validate public settings and translate them into the admin email-action request. */
export function buildEmailActionRequest(
    requestType: EmailActionType,
    email: string,
    settings?: ActionCodeSettings,
    newEmail?: string
):
    | { data: EmailActionRequest; error: null }
    | { data: null; error: FirebaseEdgeError } {
    try {
        if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+$/.test(email))
            throw new Error('A valid email address is required.');
        if (
            requestType === 'VERIFY_AND_CHANGE_EMAIL' &&
            (typeof newEmail !== 'string' ||
                !/^[^\s@]+@[^\s@]+$/.test(newEmail))
        )
            throw new Error('A valid new email address is required.');
        if (requestType === 'EMAIL_SIGNIN' && settings === undefined)
            throw new Error(
                'ActionCodeSettings are required for email sign-in.'
            );
        const data: EmailActionRequest = {
            requestType,
            email,
            returnOobLink: true
        };
        if (requestType === 'VERIFY_AND_CHANGE_EMAIL') data.newEmail = newEmail;
        if (settings === undefined) return { data, error: null };
        if (
            !settings ||
            typeof settings !== 'object' ||
            Array.isArray(settings)
        )
            throw new Error('ActionCodeSettings must be an object.');
        if (typeof settings.url !== 'string' || !settings.url.length)
            throw new Error('A valid continue URL is required.');
        const url = new URL(settings.url);
        if (!url.hostname || !['https:', 'http:'].includes(url.protocol))
            throw new Error('A valid HTTP or HTTPS continue URL is required.');
        if (
            settings.handleCodeInApp !== undefined &&
            typeof settings.handleCodeInApp !== 'boolean'
        )
            throw new Error('handleCodeInApp must be a boolean.');
        data.continueUrl = settings.url;
        data.canHandleCodeInApp = settings.handleCodeInApp ?? false;
        for (const key of ['dynamicLinkDomain', 'linkDomain'] as const) {
            if (settings[key] === undefined) continue;
            if (typeof settings[key] !== 'string' || !settings[key].length)
                throw new Error(`${key} must be a nonempty string.`);
            data[key] = settings[key];
        }
        if (settings.iOS !== undefined) {
            if (
                !settings.iOS ||
                typeof settings.iOS.bundleId !== 'string' ||
                !settings.iOS.bundleId.length
            )
                throw new Error('iOS.bundleId must be a nonempty string.');
            data.iOSBundleId = settings.iOS.bundleId;
        }
        if (settings.android !== undefined) {
            const android = settings.android;
            if (
                !android ||
                typeof android.packageName !== 'string' ||
                !android.packageName.length
            )
                throw new Error(
                    'android.packageName must be a nonempty string.'
                );
            if (
                android.installApp !== undefined &&
                typeof android.installApp !== 'boolean'
            )
                throw new Error('android.installApp must be a boolean.');
            if (
                android.minimumVersion !== undefined &&
                (typeof android.minimumVersion !== 'string' ||
                    !android.minimumVersion.length)
            )
                throw new Error(
                    'android.minimumVersion must be a nonempty string.'
                );
            data.androidPackageName = android.packageName;
            data.androidInstallApp = android.installApp ?? false;
            if (android.minimumVersion !== undefined)
                data.androidMinimumVersion = android.minimumVersion;
        }
        return { data, error: null };
    } catch (cause) {
        return {
            data: null,
            error: new FirebaseEdgeError({
                ...FirebaseAdminAuthErrorInfo.ADMIN_API_INVALID_ARGUMENT,
                message: ensureError(cause).message
            })
        };
    }
}
