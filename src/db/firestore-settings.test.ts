import { expect, it } from 'vitest';
import { validateSettings } from './firestore-settings.js';

it('accepts supported edge settings', () => {
    expect(() => validateSettings({})).not.toThrow();
    expect(() =>
        validateSettings({
            projectId: 'p',
            databaseId: 'db',
            credentials: { client_email: 'email', private_key: 'key' },
            host: 'localhost:8080',
            ssl: false,
            preferRest: true,
            ignoreUndefinedProperties: true
        })
    ).not.toThrow();
});

it.each([
    { useBigInt: 'true' },
    null,
    [],
    { databaseId: 3 },
    { projectId: 'a/b' },
    { credentials: null },
    { credentials: {} },
    { ignoreUndefinedProperties: 'true' },
    { preferRest: false },
    { keyFilename: '/key.json' }
])('rejects invalid or unsupported settings: %j', (settings) => {
    expect(() => validateSettings(settings as never)).toThrow();
});

it('validates port and implicit ordering options', () => {
    expect(() =>
        validateSettings({ port: 8080, alwaysUseImplicitOrderBy: true })
    ).not.toThrow();
    for (const port of [0, -1, 65536, 1.5, NaN])
        expect(() => validateSettings({ port })).toThrow();
    expect(() =>
        validateSettings({ alwaysUseImplicitOrderBy: 'true' as never })
    ).toThrow();
});

it('validates optional dependency-free telemetry injection', () => {
    expect(() => validateSettings({ openTelemetry: {} })).not.toThrow();
    expect(() =>
        validateSettings({
            openTelemetry: {
                tracerProvider: {
                    getTracer: () => ({ startSpan: () => ({ end() {} }) })
                }
            }
        })
    ).not.toThrow();
    expect(() => validateSettings({ openTelemetry: null as never })).toThrow();
    expect(() =>
        validateSettings({ openTelemetry: { tracerProvider: {} as never } })
    ).toThrow();
});
