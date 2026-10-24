import { FirebaseEdgeError } from '../auth/errors.js';
import type {
    DefaultConfig,
    EvaluationContext,
    ServerTemplateData,
    ServerTemplateDataType,
    ServerConfig,
    Value,
    ValueSource,
    InitServerTemplateOptions
} from './remote-config-types.js';
import { normalizeTemplate } from './remote-config-template.js';
import { evaluateCondition } from './condition-evaluator.js';
import {
    invalidRemoteConfig,
    isRemoteConfigObject,
    remoteConfigError,
    type RemoteConfigResult
} from './remote-config-results.js';

/** @internal */
export class ConfigValue implements Value {
    constructor(
        private readonly source: ValueSource,
        private readonly value = ''
    ) {}
    asString(): string {
        return this.value;
    }
    asBoolean(): boolean {
        return (
            this.source !== 'static' &&
            ['1', 'true', 't', 'yes', 'y', 'on'].includes(
                this.value.toLowerCase()
            )
        );
    }
    asNumber(): number {
        if (this.source === 'static') {
            return 0;
        }
        const number = Number(this.value);
        return Number.isNaN(number) ? 0 : number;
    }
    getSource(): ValueSource {
        return this.source;
    }
}

/** @internal */
export class EvaluatedServerConfig implements ServerConfig {
    constructor(private readonly values: Record<string, Value>) {}
    getValue(key: string): Value {
        return Object.hasOwn(this.values, key)
            ? this.values[key]!
            : new ConfigValue('static');
    }
    getString(key: string): string {
        return this.getValue(key).asString();
    }
    getBoolean(key: string): boolean {
        return this.getValue(key).asBoolean();
    }
    getNumber(key: string): number {
        return this.getValue(key).asNumber();
    }
    getAll(): Record<string, Value> {
        return { ...this.values };
    }
}

export class ServerTemplate {
    private template?: ServerTemplateData;
    readonly defaultConfig: DefaultConfig;

    constructor(
        private readonly fetchTemplate: () => Promise<
            RemoteConfigResult<ServerTemplateData>
        >,
        options: InitServerTemplateOptions = {}
    ) {
        if (
            !isRemoteConfigObject(options) ||
            (options.defaultConfig !== undefined &&
                !isRemoteConfigObject(options.defaultConfig))
        ) {
            invalidRemoteConfig(
                'Server template options and defaultConfig must be objects.'
            );
        }
        this.defaultConfig = { ...options.defaultConfig };
        for (const value of Object.values(this.defaultConfig)) {
            if (!['string', 'number', 'boolean'].includes(typeof value)) {
                invalidRemoteConfig(
                    'Default values must be strings, numbers, or booleans.'
                );
            }
        }
        if (options.template !== undefined) {
            const { error } = this.set(options.template);
            if (error) {
                throw error;
            }
        }
    }

    async load(): Promise<RemoteConfigResult<void>> {
        try {
            const { error, data } = await this.fetchTemplate();
            if (error) {
                return { error, data: null };
            }
            return this.set(data);
        } catch (cause) {
            return { error: remoteConfigError(cause), data: null };
        }
    }

    set(input: ServerTemplateDataType): RemoteConfigResult<void> {
        try {
            const parsed =
                typeof input === 'string' ? JSON.parse(input) : input;
            this.template = normalizeTemplate<ServerTemplateData>(parsed);
            return { error: null, data: undefined };
        } catch (cause) {
            return { error: remoteConfigError(cause), data: null };
        }
    }

    async evaluate(
        context: EvaluationContext = {}
    ): Promise<RemoteConfigResult<ServerConfig>> {
        try {
            if (!this.template) {
                throw new FirebaseEdgeError({
                    code: 'remote-config/failed-precondition',
                    message: 'Load or set a server template before evaluation.'
                });
            }
            if (!isRemoteConfigObject(context)) {
                invalidRemoteConfig('Evaluation context must be an object.');
            }
            const matches: string[] = [];
            for (const named of this.template.conditions) {
                const matched = await evaluateCondition(
                    named.condition,
                    context
                );
                if (matched) {
                    matches.push(named.name);
                }
            }
            const values: Record<string, Value> = Object.create(null);
            for (const [key, value] of Object.entries(this.defaultConfig)) {
                values[key] = new ConfigValue('default', String(value));
            }
            for (const [key, parameter] of Object.entries(
                this.template.parameters
            )) {
                const condition = matches.find((name) =>
                    Object.hasOwn(parameter.conditionalValues ?? {}, name)
                );
                const selected =
                    condition !== undefined
                        ? parameter.conditionalValues?.[condition]
                        : parameter.defaultValue;
                if (selected && 'value' in selected) {
                    values[key] = new ConfigValue('remote', selected.value);
                }
            }
            return { error: null, data: new EvaluatedServerConfig(values) };
        } catch (cause) {
            return { error: remoteConfigError(cause), data: null };
        }
    }

    toJSON(): ServerTemplateData | undefined {
        if (!this.template) {
            return undefined;
        }
        return JSON.parse(JSON.stringify(this.template)) as ServerTemplateData;
    }
}
