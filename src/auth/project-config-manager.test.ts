import { expect, it, vi } from 'vitest';
import { ProjectConfigManager } from './project-config-manager.js';
import type { AuthConfigExecutor } from './auth-config-types.js';

it('coordinates project reads and updates and returns executor results', async () => {
    const execute = vi
        .fn<AuthConfigExecutor>()
        .mockResolvedValue({ data: {}, error: null });
    const manager = new ProjectConfigManager(execute as AuthConfigExecutor);
    const properties = {
        emailPrivacyConfig: { enableImprovedEmailPrivacy: true }
    };
    const read = await manager.getProjectConfig();
    const update = await manager.updateProjectConfig(properties);
    expect(read).toEqual({ data: {}, error: null });
    expect(update).toEqual(read);
    expect(execute.mock.calls).toEqual([
        [{ resource: 'project', action: 'get' }],
        [{ resource: 'project', action: 'update', properties }]
    ]);
});
