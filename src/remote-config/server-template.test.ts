import { expect, it, vi } from 'vitest';
import {
    ServerTemplate,
    ConfigValue,
    EvaluatedServerConfig
} from './server-template.js';
import type { InitServerTemplateOptions } from './remote-config-types.js';

const initial = { etag: 'tag', parameters: {}, conditions: [] };

it('loads, sets, serializes, and preserves the last template after failure', async () => {
    const loader = vi.fn().mockResolvedValue({ error: null, data: initial });
    const template = new ServerTemplate(loader);
    expect(template.toJSON()).toBeUndefined();
    const evaluationResult1 = await template.evaluate();
    expect(evaluationResult1.error?.code).toBe(
        'remote-config/failed-precondition'
    );
    const evaluationResult2 = await template.load();
    expect(evaluationResult2.error).toBeNull();
    expect(template.toJSON()).toEqual(initial);
    expect(
        template.set(JSON.stringify({ ...initial, etag: 'second' })).error
    ).toBeNull();
    expect(template.set('{').error).not.toBeNull();
    expect(template.toJSON()?.etag).toBe('second');
    loader.mockRejectedValueOnce(new Error('offline'));
    const evaluationResult3 = await template.load();
    expect(evaluationResult3.error).not.toBeNull();
    expect(template.toJSON()?.etag).toBe('second');
    loader.mockResolvedValueOnce({ error: new Error('failure'), data: null });
    const evaluationResult4 = await template.load();
    expect(evaluationResult4.data).toBeNull();
});

it('evaluates condition priority, remote defaults, application defaults, and static values', async () => {
    const template = new ServerTemplate(vi.fn(), {
        defaultConfig: {
            fallback: 'app',
            enabled: true,
            count: 5,
            kept: 'app',
            experiment: 'app'
        },
        template: {
            etag: 'tag',
            conditions: [
                { name: 'first', condition: { true: {} } },
                { name: 'second', condition: { true: {} } }
            ],
            parameters: {
                greeting: {
                    defaultValue: { value: 'default' },
                    conditionalValues: {
                        second: { value: 'second' },
                        first: { value: 'first' }
                    }
                },
                remote: { defaultValue: { value: '42' } },
                kept: {
                    defaultValue: { value: 'remote' },
                    conditionalValues: { first: { useInAppDefault: true } }
                },
                experiment: {
                    conditionalValues: {
                        first: {
                            experimentValue: {
                                experimentId: 'id',
                                variantValue: []
                            }
                        }
                    }
                },
                missing: {},
                useDefault: { defaultValue: { useInAppDefault: true } },
                invalidNumber: { defaultValue: { value: 'invalid' } }
            }
        }
    });
    const { error, data } = await template.evaluate();
    expect(error).toBeNull();
    expect(data?.getString('greeting')).toBe('first');
    expect(data?.getNumber('remote')).toBe(42);
    expect(data?.getValue('remote').getSource()).toBe('remote');
    expect(data?.getString('fallback')).toBe('app');
    expect(data?.getString('kept')).toBe('app');
    expect(data?.getString('experiment')).toBe('app');
    expect(data?.getBoolean('enabled')).toBe(true);
    expect(data?.getNumber('count')).toBe(5);
    expect(data?.getValue('fallback').getSource()).toBe('default');
    expect(data?.getValue('missing').getSource()).toBe('static');
    expect(data?.getValue('missing').asNumber()).toBe(0);
    expect(data?.getValue('missing').asBoolean()).toBe(false);
    expect(data?.getNumber('invalidNumber')).toBe(0);
    expect(data?.getString('toString')).toBe('');
    const all = data!.getAll();
    delete all.remote;
    expect(data?.getNumber('remote')).toBe(42);
    const json = template.toJSON()!;
    json.parameters.remote = {};
    expect(template.toJSON()?.parameters.remote?.defaultValue).toEqual({
        value: '42'
    });
    const evaluationResult5 = await template.evaluate(null as never);
    expect(evaluationResult5.error?.code).toBe(
        'remote-config/invalid-argument'
    );
});

it.each(['1', 'TRUE', 't', 'yes', 'Y', 'on'])(
    'recognizes boolean %s',
    (input) => {
        const value = new ConfigValue('remote', input);
        expect(value.asBoolean()).toBe(true);
        expect(value.asString()).toBe(input);
    }
);

it('handles static values and getters without inherited keys', () => {
    const config = new EvaluatedServerConfig({
        number: new ConfigValue('remote', '2.5')
    });
    expect(config.getNumber('number')).toBe(2.5);
    expect(config.getString('__proto__')).toBe('');
    expect(new ConfigValue('static', 'true').asBoolean()).toBe(false);
    expect(new ConfigValue('static', '123').asNumber()).toBe(0);
    expect(new ConfigValue('remote', 'false').asBoolean()).toBe(false);
});

it.each([
    null,
    { defaultConfig: [] },
    { defaultConfig: { value: null } },
    { template: '{}' }
])('rejects invalid initialization %j', (options) => {
    expect(
        () => new ServerTemplate(vi.fn(), options as InitServerTemplateOptions)
    ).toThrow();
});
