import type {
    CookieOptions,
    GetSession,
    SetSession,
} from './auth/cookie-types.js';
import { FirebaseAdminAuth } from './auth/firebase-admin-auth.js';
import { FirebaseAuth } from './auth/firebase-auth.js';
import { signJWTCustomToken } from './auth/firebase-jwt.js';
import type { FirebaseConfig, ServiceAccount } from './auth/firebase-types.js';
import {
    createGoogleOAuthLoginUrl,
    exchangeCodeForGoogleIdToken,
} from './auth/google-oauth.js';

const DEFAULT_SESSION_NAME = '__session';

const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 5 * 1000,
} as CookieOptions;

export const OFFICIAL_FIREBASE_OAUTH_PROVIDERS = [
    'google',
    'facebook',
    'apple',
    'twitter',
    'github',
    'microsoft',
    'yahoo',
    'playgames',
] as const;

type ProviderList = (typeof OFFICIAL_FIREBASE_OAUTH_PROVIDERS)[number];

type ProviderConfig = Partial<
    Record<
        ProviderList,
        {
            client_id: string;
            client_secret: string;
        }
    >
>;

type CookieConfig = {
    getSession: GetSession;
    saveSession: SetSession;
    sessionName?: string;
};

export function createFirebaseEdgeServer({
    serviceAccount,
    firebaseConfig,
    providers,
    cookies,
    fetch,
}: {
    serviceAccount: ServiceAccount;
    firebaseConfig: FirebaseConfig;
    providers: ProviderConfig;
    cookies: CookieConfig;
    fetch?: typeof globalThis.fetch;
}) {
    const sessionName = cookies.sessionName || DEFAULT_SESSION_NAME;
    const getSession = cookies.getSession;
    const saveSession = cookies.saveSession;

    const fetchImpl = fetch ?? globalThis.fetch;

    const auth = new FirebaseAuth(firebaseConfig, fetchImpl);
    const adminAuth = new FirebaseAdminAuth(serviceAccount, fetchImpl);

    function deleteSession() {
        saveSession(sessionName, '', {
            ...COOKIE_OPTIONS,
            maxAge: 0,
        });
    }

    function signOut() {
        deleteSession();
        return;
    }

    async function getUser(checkRevoked: boolean = false) {
        const sessionCookie = await getSession(sessionName);

        if (!sessionCookie) {
            return {
                data: null,
                error: null,
            };
        }

        const { data: decodedToken, error: verifyError } =
            await adminAuth.verifySessionCookie(sessionCookie, checkRevoked);

        if (verifyError) {
            deleteSession();

            return {
                data: null,
                error: verifyError,
            };
        }

        if (!decodedToken) {
            deleteSession();

            return {
                data: null,
                error: null,
            };
        }

        return {
            data: decodedToken,
            error: null,
        };
    }

    async function getGoogleLoginURL(redirect_uri: string, path: string) {
        deleteSession();

        if (!providers.google) {
            throw new Error('Google provider not configured');
        }

        const { client_id } = providers.google;

        return createGoogleOAuthLoginUrl(redirect_uri, path, client_id);
    }

    async function signInWithGoogleWithCode(
        code: string,
        redirect_uri: string,
    ) {
        if (!providers.google) {
            return {
                error: new Error('Google provider not configured'),
            };
        }

        const { client_id, client_secret } = providers.google;

        const { data: exchangeData, error: exchangeError } =
            await exchangeCodeForGoogleIdToken(
                code,
                redirect_uri,
                client_id,
                client_secret,
                fetchImpl,
            );

        if (exchangeError) {
            return {
                error: exchangeError,
            };
        }

        if (!exchangeData) {
            return {
                error: new Error('No exchange data!'),
            };
        }

        const { data: signInData, error: signInError } =
            await auth.signInWithProvider(exchangeData.id_token, redirect_uri);

        if (signInError) {
            console.error(JSON.stringify(signInError));
            return {
                data: null,
                error: signInError,
            };
        }

        if (!signInData) {
            return {
                data: null,
                error: null,
            };
        }

        const { data: sessionCookie, error: sessionError } =
            await adminAuth.createSessionCookie(signInData.idToken, {
                expiresIn: 60 * 60 * 24 * 5 * 1000,
            });

        if (sessionError) {
            return {
                error: sessionError,
            };
        }

        if (!sessionCookie) {
            return {
                error: new Error('No session cookie returned'),
            };
        }

        saveSession(sessionName, sessionCookie, COOKIE_OPTIONS);

        return {
            error: null,
        };
    }

    async function getToken() {
        const { data: verifiedToken, error: verifyError } = await getUser();

        if (verifyError) {
            return {
                data: null,
                error: verifyError,
            };
        }

        if (!verifiedToken) {
            return {
                data: null,
                error: null,
            };
        }

        const { data: signJWTData, error: signJWTError } =
            await signJWTCustomToken(verifiedToken.sub, serviceAccount);

        if (signJWTError) {
            return {
                data: null,
                error: signJWTError,
            };
        }

        if (!signJWTData) {
            return {
                data: null,
                error: new Error('No custom token signed'),
            };
        }

        const { data: signInData, error: signInError } =
            await auth.signInWithCustomToken(signJWTData);

        if (signInError) {
            console.error(signInError);
            return {
                data: null,
                error: signInError,
            };
        }

        if (!signInData) {
            return {
                data: null,
                error: null,
            };
        }

        return {
            data: signInData,
            error: null,
        };
    }

    return {
        auth,
        adminAuth,
        signOut,
        getUser,
        getGoogleLoginURL,
        signInWithGoogleWithCode,
        getToken,
    };
}
