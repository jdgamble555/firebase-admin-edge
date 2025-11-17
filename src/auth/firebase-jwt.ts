import {
    decodeProtectedHeader,
    errors,
    jwtVerify,
    importPKCS8,
    SignJWT,
    importX509,
    importSPKI,
    type JWTPayload
} from 'jose';
import {
    JOSEError,
    JWSInvalid,
    JWSSignatureVerificationFailed,
    JWTClaimValidationFailed,
    JWTExpired,
    JWTInvalid
} from 'jose/errors';
import type {
    FirebaseIdTokenPayload,
    ServiceAccount
} from './firebase-types.js';
import { getJWKs, getPublicKeys } from './firebase-auth-endpoints.js';

const ALGORITHM_RS256 = 'RS256' as const;

const OAUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token';

const SCOPES = [
    'https://www.googleapis.com/auth/datastore',
    'https://www.googleapis.com/auth/identitytoolkit',
    'https://www.googleapis.com/auth/devstorage.read_write',
    'https://www.googleapis.com/auth/devstorage.read_write'
] as const;

const keyMap = new Map<string, typeof CryptoKey.prototype>();

async function importPublicCryptoKey(publicKey: string) {
    if (publicKey.startsWith('-----BEGIN CERTIFICATE-----')) {
        return importX509(publicKey, ALGORITHM_RS256);
    }

    return importSPKI(publicKey, ALGORITHM_RS256);
}

async function getPublicCryptoKey(publicKey: string) {
    const cachedKey = keyMap.get(publicKey);

    if (cachedKey) {
        return cachedKey;
    }

    const key = await importPublicCryptoKey(publicKey);
    keyMap.set(publicKey, key);
    return key;
}

type SignJwtResult =
    | { data: string; error: null }
    | {
          data: null;
          error: JOSEError | Error | { message: string };
      };

export async function verifySessionJWT(
    sessionCookie: string,
    projectId: string,
    fetchFn: typeof globalThis.fetch = globalThis.fetch
) {
    try {
        const { data: keyData, error } = await getPublicKeys(fetchFn);

        if (error) {
            return {
                data: null,
                error
            };
        }

        if (!keyData) {
            return {
                data: null,
                error: new Error('No public keys retrieved')
            };
        }

        // Decode header to get kid
        const header = decodeProtectedHeader(sessionCookie);

        if (
            !header.kid ||
            typeof header.kid !== 'string' ||
            !keyData[header.kid]
        ) {
            return {
                error: new Error('Invalid session cookie: no KID found'),
                data: null
            };
        }

        const publicKeyString = keyData[header.kid];

        if (!publicKeyString) {
            return {
                error: new Error('No public key found for the given KID'),
                data: null
            };
        }

        const expectedIssuer = `https://session.firebase.google.com/${projectId}`;
        const expectedAudience = projectId;

        // Non-emulator: verify with jose
        const publicKey = await getPublicCryptoKey(publicKeyString);

        const { payload } = await jwtVerify(sessionCookie, publicKey, {
            issuer: expectedIssuer,
            audience: expectedAudience,
            algorithms: [ALGORITHM_RS256]
        });

        return {
            error: null,
            data: payload as FirebaseIdTokenPayload
        };
    } catch (err) {
        if (err instanceof JWTExpired) {
            return {
                error: new Error('JWT has expired'),
                data: null
            };
        }

        if (err instanceof JWTClaimValidationFailed) {
            return {
                error: new Error(`JWT claim validation failed: ${err.message}`),
                data: null
            };
        }

        if (
            err instanceof JWSInvalid ||
            err instanceof JWSSignatureVerificationFailed
        ) {
            return {
                error: new Error('JWT signature verification failed'),
                data: null
            };
        }

        return {
            error: new Error(
                err instanceof Error
                    ? err.message
                    : 'Unknown error during JWT verification'
            ),
            data: null
        };
    }
}

export async function verifyJWT(
    idToken: string,
    projectId: string,
    fetchFn?: typeof globalThis.fetch
) {
    try {
        const { kid } = decodeProtectedHeader(idToken);

        if (!kid) {
            return {
                error: new Error('Invalid ID token: no KID found'),
                data: null
            };
        }

        const { data, error } = await getJWKs(fetchFn);

        if (error) {
            return {
                error,
                data: null
            };
        }

        if (!data || !data.length) {
            return {
                error: new Error('No JWKs retrieved'),
                data: null
            };
        }

        const jwk = data.find((key: { kid: string }) => key.kid === kid);

        if (!jwk) {
            return {
                error: new Error(`No matching JWK found for KID: ${kid}`),
                data: null
            };
        }

        const { payload } = await jwtVerify(idToken, jwk, {
            issuer: `https://securetoken.google.com/${projectId}`,
            audience: projectId,
            algorithms: ['RS256']
        });

        return {
            error: null,
            data: payload as FirebaseIdTokenPayload
        };
    } catch (err) {
        if (err instanceof JWTExpired) {
            return {
                error: new Error('JWT has expired'),
                data: null
            };
        }

        if (err instanceof JWTClaimValidationFailed) {
            return {
                error: new Error(`JWT claim validation failed: ${err.message}`),
                data: null
            };
        }

        if (
            err instanceof JWTInvalid ||
            err instanceof JWSSignatureVerificationFailed
        ) {
            return {
                error: new Error('JWT signature verification failed'),
                data: null
            };
        }

        return {
            error: new Error(
                err instanceof Error
                    ? err.message
                    : 'Unknown error during JWT verification'
            ),
            data: null
        };
    }
}

export async function signJWT(
    serviceAccount: ServiceAccount
): Promise<SignJwtResult> {
    const { private_key, client_email } = serviceAccount;

    try {
        // Normalize Firebase JSON private key
        const normalizedKey = private_key.replace(/\\n/g, '\n');

        let key;

        try {
            // NOTE: we don't type this as KeyLike, just let jose's type defs handle it
            key = await importPKCS8(normalizedKey, ALGORITHM_RS256);
        } catch (e) {
            return {
                data: null,
                error: new Error(
                    'Failed to import private key. Please ensure the private key is correctly formatted.'
                )
            };
        }

        const now = Math.floor(Date.now() / 1000);

        const payload: JWTPayload = {
            scope: SCOPES.join(' '),
            iss: client_email,
            sub: client_email,
            aud: OAUTH_TOKEN_URL,
            iat: now,
            exp: now + 3600 // 1 hour
        };

        const token = await new SignJWT(payload)
            .setProtectedHeader({ alg: ALGORITHM_RS256, typ: 'JWT' })
            .sign(key);

        return {
            data: token,
            error: null
        };
    } catch (e) {
        if (e instanceof JOSEError) {
            return { data: null, error: new Error(`JOSE Error: ${e.message}`) };
        }

        if (e instanceof Error) {
            return { data: null, error: new Error(`Error: ${e.message}`) };
        }

        return {
            data: null,
            error: new Error('Unknown error during JWT signing')
        };
    }
}

const RESERVED_CLAIMS = [
    'acr',
    'amr',
    'at_hash',
    'aud',
    'auth_time',
    'azp',
    'cnf',
    'c_hash',
    'exp',
    'iat',
    'iss',
    'jti',
    'nbf',
    'nonce',
    'sub',
    'firebase',
    'user_id'
];

export async function signJWTCustomToken(
    uid: string,
    serviceAccount: ServiceAccount,
    additionalClaims: object = {}
) {
    const { private_key, client_email } = serviceAccount;

    if (
        Object.keys(additionalClaims).some(
            (k) => RESERVED_CLAIMS.includes(k) || k.startsWith('firebase')
        )
    ) {
        return {
            data: null,
            error: new Error(
                `Reserved claims (${RESERVED_CLAIMS.join(', ')}) cannot be used in additionalClaims`
            )
        };
    }

    const payload: Record<string, unknown> = { uid };
    if (Object.keys(additionalClaims).length) {
        payload.claims = additionalClaims;
    }

    const url =
        'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';

    try {
        const key = await importPKCS8(private_key, 'RS256');

        const token = await new SignJWT(payload)
            .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
            .setIssuer(client_email)
            .setSubject(client_email)
            .setAudience(url)
            .setIssuedAt()
            .setExpirationTime('1h')
            .sign(key);

        return {
            data: token,
            error: null
        };
    } catch (e) {
        if (e instanceof errors.JOSEError) {
            return {
                data: null,
                error: new Error(`JOSE Error: ${e.message}`)
            };
        }
        if (e instanceof Error) {
            return {
                data: null,
                error: new Error(`Error: ${e.message}`)
            };
        }
        return {
            data: null,
            error: new Error('Unknown error during JWT signing')
        };
    }
}
