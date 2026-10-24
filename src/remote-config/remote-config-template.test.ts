import { expect, it } from 'vitest';
import {
    RemoteConfigTemplate,
    normalizeTemplate,
    normalizeVersion,
    validateVersionNumber
} from './remote-config-template.js';

it('normalizes templates, versions and serializes round trips', () => {
    const template = new RemoteConfigTemplate({
        etag: 'tag',
        version: {
            versionNumber: '9223372036854775807',
            updateTime: '2025-01-01',
            updateUser: { email: 'admin@example.com' },
            isLegacy: false
        }
    } as never);
    expect(template.toJSON()).toMatchObject({
        parameters: {},
        parameterGroups: {},
        conditions: [],
        etag: 'tag',
        version: { updateTime: 'Wed, 01 Jan 2025 00:00:00 GMT' }
    });
    expect(new RemoteConfigTemplate(template).toJSON()).toEqual(
        template.toJSON()
    );
    expect(normalizeTemplate({ etag: 'tag' } as never)).toMatchObject({
        parameters: {},
        conditions: []
    });
    expect(validateVersionNumber(123)).toBe('123');
    const version = normalizeVersion({ versionNumber: '2' });
    expect(version.toJSON()).toEqual({ versionNumber: '2' });
});

it.each([
    null,
    {},
    { etag: '' },
    { etag: 'tag', parameters: [] },
    { etag: 'tag', parameterGroups: null },
    { etag: 'tag', conditions: {} },
    { etag: 'tag', parameters: { bad: null } }
])('rejects invalid template %j', (input) => {
    expect(() => new RemoteConfigTemplate(input as never)).toThrow();
});

it.each([
    null,
    { updateTime: 'bad' },
    { versionNumber: 0 },
    { updateUser: null },
    { isLegacy: 'yes' },
    { description: 1 },
    { updateOrigin: 2 },
    { updateType: false }
])('rejects invalid version %j', (input) => {
    expect(() => normalizeVersion(input as never)).toThrow();
});

it('validates experiment exposure in parameters and parameter groups', () => {
    for (const exposurePercent of [-1, 101, NaN, '5']) {
        const parameter = {
            conditionalValues: {
                users: {
                    experimentValue: {
                        experimentId: 'id',
                        variantValue: [],
                        exposurePercent
                    }
                }
            }
        };
        for (const data of [
            { parameters: { test: parameter } },
            { parameterGroups: { group: { parameters: { test: parameter } } } }
        ]) {
            expect(
                () =>
                    new RemoteConfigTemplate({ etag: 'tag', ...data } as never)
            ).toThrow('exposure');
        }
    }
});
