import type {
    AuthConfigExecutor,
    ProjectConfig,
    UpdateProjectConfigRequest
} from './auth-config-types.js';

/** Manage the configuration of the parent Identity Platform project. */
export class ProjectConfigManager {
    /** @internal Obtain this manager from adminAuth.projectConfigManager(). */
    constructor(private readonly execute: AuthConfigExecutor) {}

    getProjectConfig() {
        return this.execute<ProjectConfig>({
            resource: 'project',
            action: 'get'
        });
    }

    updateProjectConfig(properties: UpdateProjectConfigRequest) {
        return this.execute<ProjectConfig>({
            resource: 'project',
            action: 'update',
            properties
        });
    }
}
