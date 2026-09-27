import { importPKCS8, SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type { ServiceAccount } from '../auth/firebase-types.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { createAppCheckKeyResolver } from './app-check-endpoints.js';

export interface DecodedAppCheckToken extends JWTPayload {
    app_id: string;
    sub: string;
    aud: string[];
    iss: string;
    iat: number;
    exp: number;
}

/** @internal Sign the short-lived assertion used by a custom provider. */
export async function signAppCheckToken(
    account: ServiceAccount,
    appId: string,
    ttlMillis?: number
) {
    if (
        typeof appId !== 'string' ||
        !appId.trim() ||
        (ttlMillis !== undefined &&
            (!Number.isFinite(ttlMillis) ||
                ttlMillis < 1800000 ||
                ttlMillis > 604800000))
    ) {
        throw new FirebaseEdgeError({
            code: 'app-check/invalid-argument',
            message:
                'Provide an app ID and a TTL between 30 minutes and 7 days.'
        });
    }
    const key = await importPKCS8(
        account.private_key.replace(/\\n/g, '\n'),
        'RS256'
    );
    return new SignJWT({
        app_id: appId,
        ...(ttlMillis !== undefined && { ttl: `${ttlMillis / 1000}s` })
    })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setIssuer(account.client_email)
        .setSubject(account.client_email)
        .setAudience(
            'https://firebaseappcheck.googleapis.com/google.firebase.appcheck.v1.TokenExchangeService'
        )
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(key);
}

/** @internal Verify signatures before trusting any App Check claims. */
export async function verifyAppCheckToken(
    token: string,
    projectId: string,
    keys: ReturnType<typeof createAppCheckKeyResolver>
): Promise<DecodedAppCheckToken> {
    if (typeof token !== 'string' || !token.trim()) {
        throw new FirebaseEdgeError({
            code: 'app-check/invalid-argument',
            message: 'Provide an App Check token.'
        });
    }
    const { payload, protectedHeader } = await jwtVerify(token, keys, {
        algorithms: ['RS256'],
        audience: `projects/${projectId}`,
        requiredClaims: ['iss', 'sub', 'aud', 'iat', 'exp']
    });
    if (
        typeof protectedHeader.kid !== 'string' ||
        !protectedHeader.kid ||
        !Array.isArray(payload.aud) ||
        typeof payload.iss !== 'string' ||
        !/^https:\/\/firebaseappcheck\.googleapis\.com\/[^/]+$/.test(
            payload.iss
        ) ||
        typeof payload.sub !== 'string' ||
        !payload.sub.trim() ||
        typeof payload.iat !== 'number' ||
        payload.iat > Date.now() / 1000 ||
        payload.exp! <= payload.iat
    ) {
        throw new FirebaseEdgeError({
            code: 'app-check/invalid-argument',
            message: 'Invalid App Check token claims.'
        });
    }
    return { ...payload, app_id: payload.sub } as DecodedAppCheckToken;
}
