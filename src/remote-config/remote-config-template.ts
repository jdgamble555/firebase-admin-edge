import type {
    RemoteConfigTemplate as TemplateData,
    ServerTemplateData,
    Version
} from './remote-config-types.js';
import {
    invalidRemoteConfig,
    isRemoteConfigObject
} from './remote-config-results.js';

/** @internal Validate and normalize version metadata without losing int64 precision. */
export function normalizeVersion(
    input: Version
): Version & { toJSON(): object } {
    if (!isRemoteConfigObject(input)) {
        invalidRemoteConfig('Version must be an object.');
    }
    const version = { ...input };
    for (const key of ['versionNumber', 'rollbackSource'] as const) {
        if (version[key] !== undefined) {
            version[key] = validateVersionNumber(version[key]);
        }
    }
    if (version.updateTime !== undefined) {
        if (
            typeof version.updateTime !== 'string' ||
            !version.updateTime.trim()
        ) {
            invalidRemoteConfig('Invalid version update time.');
        }
        const date = new Date(version.updateTime);
        if (!Number.isFinite(date.getTime())) {
            invalidRemoteConfig('Invalid version update time.');
        }
        version.updateTime = date.toUTCString();
    }
    if (
        version.updateUser !== undefined &&
        !isRemoteConfigObject(version.updateUser)
    ) {
        invalidRemoteConfig('Version updateUser must be an object.');
    }
    if (
        version.isLegacy !== undefined &&
        typeof version.isLegacy !== 'boolean'
    ) {
        invalidRemoteConfig('Version isLegacy must be a boolean.');
    }
    for (const key of ['description', 'updateOrigin', 'updateType'] as const) {
        if (version[key] !== undefined && typeof version[key] !== 'string') {
            invalidRemoteConfig(`Version ${key} must be a string.`);
        }
    }
    return Object.assign(version, {
        toJSON() {
            const { toJSON, ...data } = this;
            return data;
        }
    });
}

/** @internal */
export function validateVersionNumber(value: string | number): string {
    if (
        (typeof value !== 'string' && typeof value !== 'number') ||
        (typeof value === 'number' && !Number.isSafeInteger(value)) ||
        !/^[1-9]\d*$/.test(String(value))
    ) {
        invalidRemoteConfig(
            'Version number must be a positive integer or int64 string.'
        );
    }
    if (BigInt(value) > 9223372036854775807n) {
        invalidRemoteConfig('Version number exceeds int64 range.');
    }
    return String(value);
}

/** @internal */
export function normalizeTemplate<T extends TemplateData | ServerTemplateData>(
    input: T
): T {
    if (
        !isRemoteConfigObject(input) ||
        typeof input.etag !== 'string' ||
        !input.etag.trim()
    ) {
        invalidRemoteConfig('Template must have a non-empty ETag.');
    }
    for (const key of ['parameters', 'parameterGroups'] as const) {
        if (input[key] !== undefined && !isRemoteConfigObject(input[key])) {
            invalidRemoteConfig(`${key} must be an object.`);
        }
    }
    if (input.conditions !== undefined && !Array.isArray(input.conditions)) {
        invalidRemoteConfig('conditions must be an array.');
    }
    const template = JSON.parse(JSON.stringify(input)) as T;
    template.parameters ??= {};
    template.conditions ??= [];

    for (const parameter of [
        ...Object.values(template.parameters),
        ...Object.values((input as TemplateData).parameterGroups ?? {}).flatMap(
            (group) => Object.values(group.parameters ?? {})
        )
    ]) {
        if (!isRemoteConfigObject(parameter)) {
            invalidRemoteConfig('Each parameter must be an object.');
        }
        for (const value of Object.values(parameter.conditionalValues ?? {})) {
            if (!('experimentValue' in value)) {
                continue;
            }
            const { exposurePercent } = value.experimentValue;
            if (exposurePercent === undefined) {
                continue;
            }
            if (
                typeof exposurePercent !== 'number' ||
                !Number.isFinite(exposurePercent) ||
                exposurePercent < 0 ||
                exposurePercent > 100
            ) {
                invalidRemoteConfig(
                    'Experiment exposure percent must be between 0 and 100.'
                );
            }
        }
    }
    if (input.version !== undefined) {
        template.version = normalizeVersion(input.version);
    }
    return template;
}

/** A mutable client template with a read-only ETag and JSON serialization. */
export class RemoteConfigTemplate implements TemplateData {
    parameters: TemplateData['parameters'];
    parameterGroups: TemplateData['parameterGroups'];
    conditions: TemplateData['conditions'];
    version?: Version;
    readonly etag: string;

    constructor(input: TemplateData) {
        const template = normalizeTemplate(input);
        this.etag = template.etag;
        this.parameters = template.parameters;
        this.parameterGroups = template.parameterGroups ?? {};
        this.conditions = template.conditions;
        this.version = template.version;
    }

    toJSON(): TemplateData {
        return {
            parameters: this.parameters,
            parameterGroups: this.parameterGroups,
            conditions: this.conditions,
            etag: this.etag,
            version: this.version
                ? (normalizeVersion(this.version).toJSON() as Version)
                : undefined
        };
    }
}
