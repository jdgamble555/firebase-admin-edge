import type {
    ServiceAccount,
    GoogleTokenResponse
} from '../auth/firebase-types.js';
import type { CacheConfig } from '../auth/cache-types.js';
import { getToken } from '../auth/google-oauth.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import {
    remoteConfigRequest,
    type RemoteConfigOperation
} from './remote-config-endpoints.js';
import { RemoteConfigTemplate } from './remote-config-template.js';
import { ServerTemplate } from './server-template.js';
import {
    invalidRemoteConfig,
    isRemoteConfigObject,
    remoteConfigError,
    type RemoteConfigResult
} from './remote-config-results.js';
import type {
    RemoteConfigTemplate as TemplateData,
    ServerTemplateData,
    GetServerTemplateOptions,
    InitServerTemplateOptions,
    ListVersionsOptions,
    ListVersionsResult
} from './remote-config-types.js';

export * from './remote-config-types.js';
export type { RemoteConfigResult } from './remote-config-results.js';
export { RemoteConfigTemplate, ServerTemplate };
export { RemoteConfigFetchResponse } from './remote-config-fetch-response.js';

export interface RemoteConfigOptions {
    fetch?: typeof globalThis.fetch;
    cache?: CacheConfig;
    cacheName?: string;
}

export class RemoteConfig {
    private readonly fetch: typeof globalThis.fetch;
    constructor(
        private readonly serviceAccount: ServiceAccount,
        private readonly options: RemoteConfigOptions = {}
    ) {
        if (!serviceAccount?.project_id?.trim()) {
            invalidRemoteConfig('A service account project ID is required.');
        }
        this.fetch = options.fetch ?? globalThis.fetch;
    }

    private async request<T>(
        operation: RemoteConfigOperation
    ): Promise<RemoteConfigResult<T>> {
        try {
            const key = `${this.options.cacheName ?? '__cache'}:remote-config:${this.serviceAccount.client_email}`;
            let token =
                await this.options.cache?.getCache<GoogleTokenResponse>(key);
            if (!token?.access_token) {
                const { error, data } = await getToken(
                    this.serviceAccount,
                    this.fetch
                );
                if (error) {
                    return { error, data: null };
                }
                token = data;
                const ttl = (data.expires_in - 60) * 1000;
                if (Number.isFinite(ttl) && ttl > 0) {
                    await this.options.cache?.setCache(key, data, ttl);
                }
            }
            const data = await remoteConfigRequest(
                this.serviceAccount.project_id,
                token.access_token,
                operation,
                this.fetch
            );
            if (operation.type === 'list' || operation.type === 'server') {
                return { error: null, data: data as T };
            }
            return {
                error: null,
                data: new RemoteConfigTemplate(data as TemplateData) as T
            };
        } catch (cause) {
            return { error: remoteConfigError(cause), data: null };
        }
    }

    getTemplate(): Promise<RemoteConfigResult<RemoteConfigTemplate>> {
        return this.request({ type: 'get' });
    }
    getTemplateAtVersion(
        versionNumber: string | number
    ): Promise<RemoteConfigResult<RemoteConfigTemplate>> {
        return this.request({ type: 'get', version: versionNumber });
    }
    validateTemplate(
        template: TemplateData
    ): Promise<RemoteConfigResult<RemoteConfigTemplate>> {
        return this.request({ type: 'validate', template });
    }
    async publishTemplate(
        template: TemplateData,
        options?: { force: boolean }
    ): Promise<RemoteConfigResult<RemoteConfigTemplate>> {
        if (options !== undefined && !isRemoteConfigObject(options)) {
            return {
                error: new FirebaseEdgeError({
                    code: 'remote-config/invalid-argument',
                    message: 'Publish options must be an object.'
                }),
                data: null
            };
        }
        return this.request({
            type: 'publish',
            template,
            force: options?.force
        });
    }
    rollback(
        versionNumber: string | number
    ): Promise<RemoteConfigResult<RemoteConfigTemplate>> {
        return this.request({ type: 'rollback', version: versionNumber });
    }
    listVersions(
        options?: ListVersionsOptions
    ): Promise<RemoteConfigResult<ListVersionsResult>> {
        return this.request({ type: 'list', options });
    }

    createTemplateFromJSON(
        json: string
    ): RemoteConfigResult<RemoteConfigTemplate> {
        try {
            if (typeof json !== 'string' || !json.trim()) {
                invalidRemoteConfig(
                    'Template JSON must be a non-empty string.'
                );
            }
            return {
                error: null,
                data: new RemoteConfigTemplate(JSON.parse(json))
            };
        } catch (cause) {
            return { error: remoteConfigError(cause), data: null };
        }
    }

    initServerTemplate(options?: InitServerTemplateOptions): ServerTemplate {
        return new ServerTemplate(
            () => this.request<ServerTemplateData>({ type: 'server' }),
            options
        );
    }

    async getServerTemplate(
        options?: GetServerTemplateOptions
    ): Promise<RemoteConfigResult<ServerTemplate>> {
        try {
            const template = this.initServerTemplate(options);
            const { error } = await template.load();
            if (error) {
                return { error, data: null };
            }
            return { error: null, data: template };
        } catch (cause) {
            return { error: remoteConfigError(cause), data: null };
        }
    }
}
