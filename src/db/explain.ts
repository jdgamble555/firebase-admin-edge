import { FirebaseEdgeError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';

export interface ExplainOptions {
    analyze?: boolean;
}
export interface PlanSummary {
    indexesUsed: Record<string, unknown>[];
}
export interface ExecutionStats {
    resultsReturned: number;
    executionDuration: { seconds: number; nanoseconds: number };
    readOperations: number;
    debugStats: Record<string, unknown>;
}
export interface ExplainMetrics {
    planSummary: PlanSummary;
    executionStats: ExecutionStats | null;
}
export interface ExplainResults<T> {
    metrics: ExplainMetrics;
    snapshot: T | null;
}

/** @internal Validate options before any request. */
export function validateExplainOptions(options: ExplainOptions): void {
    if (
        !options ||
        typeof options !== 'object' ||
        Array.isArray(options) ||
        (options.analyze !== undefined && typeof options.analyze !== 'boolean')
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Invalid explain options.'
        });
}
/** @internal Convert protobuf JSON numbers and duration into SDK metric types. */
export function parseExplainMetrics(input: unknown): ExplainMetrics {
    const value = input as {
        planSummary?: PlanSummary;
        executionStats?: {
            resultsReturned?: string | number;
            readOperations?: string | number;
            executionDuration?: string;
            debugStats?: Record<string, unknown>;
        };
    };
    if (
        !value ||
        typeof value !== 'object' ||
        !value.planSummary ||
        (value.planSummary.indexesUsed !== undefined &&
            !Array.isArray(value.planSummary.indexesUsed))
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Invalid explain metrics.'
        });
    const result: ExplainMetrics = {
        planSummary: { indexesUsed: value.planSummary.indexesUsed ?? [] },
        executionStats: null
    };
    if (!value.executionStats) return result;
    const stats = value.executionStats;
    if (typeof stats !== 'object' || Array.isArray(stats))
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Invalid execution statistics.'
        });
    const duration = /^(\d+)(?:\.(\d{1,9}))?s$/.exec(
        stats.executionDuration ?? '0s'
    );
    const resultsReturned = Number(stats.resultsReturned ?? 0);
    const readOperations = Number(stats.readOperations ?? 0);
    if (
        !duration ||
        !Number.isSafeInteger(resultsReturned) ||
        resultsReturned < 0 ||
        !Number.isSafeInteger(readOperations) ||
        readOperations < 0
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Invalid execution statistics.'
        });
    result.executionStats = {
        resultsReturned,
        readOperations,
        executionDuration: {
            seconds: Number(duration[1]),
            nanoseconds: Number((duration[2] ?? '').padEnd(9, '0'))
        },
        debugStats: stats.debugStats ?? {}
    };
    return result;
}
