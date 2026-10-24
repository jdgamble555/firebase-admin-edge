import type { ServerConfig, FetchResponseData } from './remote-config-types.js';

/** Produces a client fetch response from evaluated server configuration. */
export class RemoteConfigFetchResponse {
    private readonly response: FetchResponseData;
    constructor(
        projectId: string,
        serverConfig: ServerConfig,
        requestEtag?: string
    ) {
        const config = Object.fromEntries(
            Object.entries(serverConfig.getAll()).map(([key, value]) => [
                key,
                value.asString()
            ])
        );
        const json = JSON.stringify(config);
        let hash = 0;
        for (let index = 0; index < json.length; index++) {
            hash = ((hash << 5) - hash + json.charCodeAt(index)) | 0;
        }
        const eTag = ['etag', projectId, 'firebase-server', 'fetch', hash]
            .filter(Boolean)
            .join('-');
        this.response =
            requestEtag === eTag
                ? { status: 304, eTag }
                : { status: 200, eTag, config };
    }
    toJSON(): FetchResponseData {
        return structuredClone(this.response);
    }
}
