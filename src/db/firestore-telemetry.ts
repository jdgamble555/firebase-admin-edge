import type { FirestoreOpenTelemetryOptions } from './firestore-settings.js';
export interface FirestoreSpan {
    end(): void;
    recordException?(error: Error): void;
    setStatus?(status: { code: number; message?: string }): void;
}
export interface FirestoreTracer {
    startSpan(name: string): FirestoreSpan;
    startActiveSpan?<T>(name: string, callback: (span: FirestoreSpan) => T): T;
}
export interface FirestoreTracerProvider {
    getTracer(name: string): FirestoreTracer;
}
/** @internal Resolve injected or registered OTel 1.x providers at operation time. */
export function getFirestoreTracer(
    options?: FirestoreOpenTelemetryOptions
): FirestoreTracer | undefined {
    try {
        const environment = (
            globalThis as unknown as {
                process?: { env?: Record<string, string | undefined> };
            }
        ).process?.env;
        if (
            ['off', 'false'].includes(
                environment?.FIRESTORE_ENABLE_TRACING?.toLowerCase() ?? ''
            )
        )
            return undefined;
        const registry = (
            globalThis as unknown as Record<
                symbol,
                { version?: string; trace?: FirestoreTracerProvider }
            >
        )[Symbol.for('opentelemetry.js.api.1')];
        const globalProvider =
            registry && /^1\.\d+\.\d+$/.test(registry.version ?? '')
                ? registry.trace
                : undefined;
        const provider = options?.tracerProvider ?? globalProvider;
        if (typeof provider?.getTracer !== 'function') return undefined;
        return provider.getTracer('firebase-admin-edge.firestore');
    } catch {
        return undefined;
    }
}
/** @internal Tracing cannot change values, errors, or execute an operation twice. */
export function traceFirestoreOperation<T>(
    name: string,
    options: FirestoreOpenTelemetryOptions | undefined,
    operation: () => Promise<T>
): Promise<T> {
    const tracer = getFirestoreTracer(options);
    let pending: Promise<T> | undefined;
    const run = (span?: FirestoreSpan): Promise<T> => {
        if (pending) return pending;
        pending = Promise.resolve()
            .then(operation)
            .then(
                (result) => {
                    try {
                        const failed =
                            result instanceof Response
                                ? !result.ok
                                : result !== null &&
                                  typeof result === 'object' &&
                                  'error' in result &&
                                  result.error != null;
                        span?.setStatus?.({ code: failed ? 2 : 1 });
                    } catch {
                        /* Preserve the result. */
                    }
                    return result;
                },
                (error: unknown) => {
                    try {
                        span?.setStatus?.({ code: 2 });
                    } catch {
                        /* Preserve the failure. */
                    }
                    try {
                        if (error instanceof Error)
                            span?.recordException?.(error);
                    } catch {
                        /* Preserve the failure. */
                    }
                    throw error;
                }
            )
            .finally(() => {
                try {
                    span?.end();
                } catch {
                    /* Preserve the outcome. */
                }
            });
        return pending;
    };
    if (!tracer) return run();
    try {
        if (typeof tracer.startActiveSpan === 'function') {
            const traced = tracer.startActiveSpan(name, run);
            void Promise.resolve(traced).catch(() => {});
            return pending ?? run();
        }
        const span = tracer.startSpan(name);
        return run(span);
    } catch {
        return pending ?? run();
    }
}
