import { firestoreData } from './firestore-results.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { afterEach, expect, it, vi } from 'vitest';
import {
    getFirestoreTracer,
    traceFirestoreOperation,
    type FirestoreSpan
} from './firestore-telemetry.js';
import { Firestore } from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
const registry = Symbol.for('opentelemetry.js.api.1');
afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
});
it('discovers compatible globals lazily and respects explicit providers and disabling', () => {
    vi.stubGlobal(registry, undefined);
    expect(getFirestoreTracer()).toBeUndefined();
    const tracer = { startSpan: vi.fn() };
    const getTracer = vi.fn().mockReturnValue(tracer);
    vi.stubGlobal(registry, { version: '1.9.0', trace: { getTracer } });
    expect(getFirestoreTracer()).toBe(tracer);
    const explicit = { startSpan: vi.fn() };
    expect(
        getFirestoreTracer({ tracerProvider: { getTracer: () => explicit } })
    ).toBe(explicit);
    for (const version of ['2.0.0', '1.9.0-beta.1', '', undefined]) {
        vi.stubGlobal(registry, { version, trace: { getTracer } });
        expect(getFirestoreTracer()).toBeUndefined();
    }
    expect(
        getFirestoreTracer({
            tracerProvider: {
                getTracer: () => {
                    throw new Error('diagnostics');
                }
            }
        })
    ).toBeUndefined();
    vi.stubEnv('FIRESTORE_ENABLE_TRACING', 'OFF');
    expect(
        getFirestoreTracer({ tracerProvider: { getTracer } })
    ).toBeUndefined();
});
it('preserves resolved data/error objects and original rejected values', async () => {
    const span = { end: vi.fn(), setStatus: vi.fn(), recordException: vi.fn() };
    const settings = {
        tracerProvider: { getTracer: () => ({ startSpan: () => span }) }
    };
    const response = { data: { n: 1 }, error: null };
    const result = await traceFirestoreOperation(
        'read',
        settings,
        async () => response
    );
    expect(result).toBe(response);
    expect(span.setStatus).toHaveBeenLastCalledWith({ code: 1 });
    const failure = { data: null, error: new Error('denied') };
    const returned = await traceFirestoreOperation(
        'read',
        settings,
        async () => failure
    );
    expect(returned).toBe(failure);
    expect(span.setStatus).toHaveBeenLastCalledWith({ code: 2 });
    await expect(
        traceFirestoreOperation('read', settings, async () => {
            throw failure.error;
        })
    ).rejects.toBe(failure.error);
    expect(span.recordException).toHaveBeenCalledWith(failure.error);
    expect(span.end).toHaveBeenCalledTimes(3);
    await expect(
        traceFirestoreOperation('read', settings, async () => {
            throw 'original';
        })
    ).rejects.toBe('original');
});
it('never reruns an operation when instrumentation throws or invokes its callback twice', async () => {
    const span = {
        end: () => {
            throw new Error('end');
        },
        setStatus: () => {
            throw new Error('status');
        }
    };
    const operation = vi.fn().mockResolvedValue(42);
    const options = {
        tracerProvider: {
            getTracer: () => ({
                startSpan: () => span,
                startActiveSpan: <T>(
                    _name: string,
                    callback: (span: FirestoreSpan) => T
                ): T => {
                    callback(span);
                    callback(span);
                    throw new Error('after callback');
                }
            })
        }
    };
    const result = await traceFirestoreOperation('read', options, operation);
    expect(result).toBe(42);
    expect(operation).toHaveBeenCalledOnce();
    const broken = {
        tracerProvider: {
            getTracer: () => ({
                startSpan: (): FirestoreSpan => {
                    throw new Error('span');
                }
            })
        }
    };
    const fallback = await traceFirestoreOperation('read', broken, operation);
    expect(fallback).toBe(42);
    expect(operation).toHaveBeenCalledTimes(2);
});
it('creates parent operation spans for writes using a global provider registered after Firestore construction', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    vi.spyOn(db, '_commit').mockResolvedValue([]);
    const context = new AsyncLocalStorage<string>();
    const events: { name: string; parent?: string }[] = [];
    const ended: string[] = [];
    const tracer = {
        startSpan: (name: string) => ({
            end: () => {
                ended.push(name);
            }
        }),
        startActiveSpan: <T>(
            name: string,
            callback: (span: FirestoreSpan) => T
        ): T => {
            events.push({ name, parent: context.getStore() });
            return context.run(name, () => callback(tracer.startSpan(name)));
        }
    };
    vi.stubGlobal(registry, {
        version: '1.9.0',
        trace: { getTracer: () => tracer }
    });
    await db.doc('users/a').set({ n: 1 }).then(firestoreData);
    expect(events).toContainEqual({
        name: 'WriteBatch.commit',
        parent: 'DocumentReference.set'
    });
    expect(ended).toEqual(['WriteBatch.commit', 'DocumentReference.set']);
});
