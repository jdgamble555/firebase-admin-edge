import { errors } from 'jose';
import { getToken } from '../auth/google-oauth.js';
import { FirebaseEdgeError, ensureError } from '../auth/errors.js';
import type {
    ServiceAccount,
    GoogleTokenResponse
} from '../auth/firebase-types.js';
import type { CacheConfig } from '../auth/cache-types.js';
import {
    appCheckRequest,
    createAppCheckKeyResolver,
    parseAppCheckToken
} from './app-check-endpoints.js';
import {
    signAppCheckToken,
    verifyAppCheckToken,
    type DecodedAppCheckToken
} from './app-check-jwt.js';
export type { DecodedAppCheckToken } from './app-check-jwt.js';

export interface AppCheckToken {
    token: string;
    ttlMillis: number;
}
export interface AppCheckTokenOptions {
    ttlMillis?: number;
    /** Issue a token that supports replay protection. Defaults to false. */
    limitedUse?: boolean;
    /** Replay identity; requires limitedUse: true. Empty or omitted lets Firebase generate it. */
    jti?: string;
}
export interface VerifyAppCheckTokenOptions {
    consume?: boolean;
}
export interface AppCheckTokenResult {
    appId: string;
    token: DecodedAppCheckToken;
    alreadyConsumed?: boolean;
}
type AppCheckResult<T> =
    | { error: null; data: T }
    | { error: FirebaseEdgeError; data: null };

export interface AppCheckOptions {
    fetch?: typeof globalThis.fetch;
    cache?: CacheConfig;
    cacheName?: string;
}

export class AppCheck {
    private readonly keys: ReturnType<typeof createAppCheckKeyResolver>;

    private readonly fetch: typeof globalThis.fetch;
    private readonly cache?: CacheConfig;
    private readonly cacheName: string;

    constructor(
        private readonly serviceAccount: ServiceAccount,
        options: AppCheckOptions = {}
    ) {
        const {
            fetch = globalThis.fetch,
            cache,
            cacheName = '__cache'
        } = options;
        if (!serviceAccount?.project_id?.trim()) {
            throw new FirebaseEdgeError({
                code: 'app-check/invalid-argument',
                message: 'A service account project ID is required.'
            });
        }

        this.fetch = fetch;
        this.cache = cache;
        this.cacheName = cacheName;
        this.keys = createAppCheckKeyResolver(fetch);
    }

    private async getAccessToken() {
        const key = `${this.cacheName}:app-check:${this.serviceAccount.client_email}`;
        const cached = await this.cache?.getCache<GoogleTokenResponse>(key);
        if (cached?.access_token) {
            return { error: null, data: cached };
        }
        const { error, data } = await getToken(this.serviceAccount, this.fetch);
        if (error) {
            return { error, data: null };
        }
        const ttlMs = (data.expires_in - 60) * 1000;
        if (Number.isFinite(ttlMs) && ttlMs > 0) {
            await this.cache?.setCache(key, data, ttlMs);
        }
        return { error: null, data };
    }

    async createToken(
        appId: string,
        options: AppCheckTokenOptions = {}
    ): Promise<AppCheckResult<AppCheckToken>> {
        try {
            if (
                !options ||
                typeof options !== 'object' ||
                Array.isArray(options)
            ) {
                throw new FirebaseEdgeError({
                    code: 'app-check/invalid-argument',
                    message: 'Token options must be an object.'
                });
            }

            const { limitedUse, jti } = options;
            if (limitedUse !== undefined && typeof limitedUse !== 'boolean') {
                throw new FirebaseEdgeError({
                    code: 'app-check/invalid-argument',
                    message: 'limitedUse must be a boolean.'
                });
            }
            if (jti !== undefined && typeof jti !== 'string') {
                throw new FirebaseEdgeError({
                    code: 'app-check/invalid-argument',
                    message: 'jti must be a string.'
                });
            }
            if (jti !== undefined && limitedUse !== true) {
                throw new FirebaseEdgeError({
                    code: 'app-check/invalid-argument',
                    message: 'jti requires limitedUse to be true.'
                });
            }

            const customToken = await signAppCheckToken(
                this.serviceAccount,
                appId,
                options.ttlMillis
            );
            const { error, data } = await this.getAccessToken();
            if (error) {
                return { error, data: null };
            }
            const response = await appCheckRequest(
                this.serviceAccount.project_id,
                data.access_token,
                {
                    appId,
                    customToken,
                    ...(limitedUse !== undefined && { limitedUse }),
                    ...(jti !== undefined && { jti })
                },
                this.fetch
            );
            return { error: null, data: parseAppCheckToken(response) };
        } catch (cause) {
            return { error: appCheckError(cause), data: null };
        }
    }

    async verifyToken(
        token: string,
        options: VerifyAppCheckTokenOptions = {}
    ): Promise<AppCheckResult<AppCheckTokenResult>> {
        try {
            if (
                !options ||
                typeof options !== 'object' ||
                Array.isArray(options) ||
                (options.consume !== undefined &&
                    typeof options.consume !== 'boolean')
            ) {
                throw new FirebaseEdgeError({
                    code: 'app-check/invalid-argument',
                    message: 'consume must be a boolean.'
                });
            }
            const decoded = await verifyAppCheckToken(
                token,
                this.serviceAccount.project_id,
                this.keys
            );
            if (!options.consume) {
                return {
                    error: null,
                    data: { appId: decoded.app_id, token: decoded }
                };
            }

            const { error, data } = await this.getAccessToken();
            if (error) {
                return { error, data: null };
            }
            const { alreadyConsumed = false } = await appCheckRequest(
                this.serviceAccount.project_id,
                data.access_token,
                { token },
                this.fetch
            );
            if (typeof alreadyConsumed !== 'boolean') {
                throw new FirebaseEdgeError({
                    code: 'app-check/internal-error',
                    message: 'Invalid replay protection response.'
                });
            }
            return {
                error: null,
                data: { appId: decoded.app_id, token: decoded, alreadyConsumed }
            };
        } catch (cause) {
            return { error: appCheckError(cause), data: null };
        }
    }
}

/** @internal Normalize thrown failures to the package result convention. */
function appCheckError(cause: unknown): FirebaseEdgeError {
    if (cause instanceof FirebaseEdgeError) {
        return cause;
    }
    return new FirebaseEdgeError(
        {
            code:
                cause instanceof errors.JWTExpired
                    ? 'app-check/app-check-token-expired'
                    : cause instanceof errors.JOSEError
                      ? 'app-check/invalid-argument'
                      : 'app-check/internal-error',
            message: 'App Check operation failed.'
        },
        { cause: ensureError(cause) }
    );
}
