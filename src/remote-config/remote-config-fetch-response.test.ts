import { expect, it } from 'vitest';
import { RemoteConfigFetchResponse } from './remote-config-fetch-response.js';
import { ConfigValue, EvaluatedServerConfig } from './server-template.js';

it('generates client fetch responses and conditional 304 responses', () => {
    const config = new EvaluatedServerConfig({
        greeting: new ConfigValue('remote', 'hello')
    });
    const response = new RemoteConfigFetchResponse('project', config).toJSON();
    expect(response).toMatchObject({
        status: 200,
        config: { greeting: 'hello' }
    });
    expect(response.eTag).toMatch(/^etag-project-firebase-server-fetch-/);
    expect(
        new RemoteConfigFetchResponse('project', config, response.eTag).toJSON()
    ).toEqual({ status: 304, eTag: response.eTag });
    response.config!.greeting = 'changed';
    expect(
        new RemoteConfigFetchResponse('project', config).toJSON().config
            ?.greeting
    ).toBe('hello');
});
