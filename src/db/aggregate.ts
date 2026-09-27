import { type FirestoreResult, firestoreResult } from './firestore-results.js';
import type { DocumentData } from './firestore-document.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { FieldPath } from './field-path.js';
import { validateFieldPath } from './query-request.js';
import type { Query } from './query.js';
import { Timestamp } from './timestamp.js';
import { valueEquals } from './value-equality.js';
import {
    validateExplainOptions,
    type ExplainOptions,
    type ExplainMetrics,
    type ExplainResults
} from './explain.js';
export const aggregateReadTime = Symbol('aggregateReadTime');
export const aggregateMetrics = Symbol('aggregateMetrics');

export class AggregateField<T = number | null> {
    declare readonly _resultType: T;
    readonly type = 'AggregateField';
    private constructor(
        readonly aggregateType: 'count' | 'sum' | 'avg',
        readonly field?: string
    ) {}
    static count(): AggregateField<number> {
        return new AggregateField('count');
    }
    static sum(field: string | FieldPath): AggregateField<number> {
        return AggregateField.forField('sum', field) as AggregateField<number>;
    }
    static average(field: string | FieldPath): AggregateField {
        return AggregateField.forField('avg', field);
    }
    private static forField(
        type: 'sum' | 'avg',
        field: string | FieldPath
    ): AggregateField {
        if (!(field instanceof FieldPath)) validateFieldPath(field);
        return new AggregateField(type, field.toString());
    }
    isEqual(other: AggregateField): boolean {
        return (
            other instanceof AggregateField &&
            this.aggregateType === other.aggregateType &&
            this.field === other.field
        );
    }
}
export type AggregateSpec = Record<string, AggregateField>;
export type AggregateData = Record<string, number | null>;

export class AggregateQuery<
    S extends AggregateSpec = AggregateSpec,
    AppModelType = DocumentData,
    DbModelType extends DocumentData = DocumentData
> {
    async explain(
        options: ExplainOptions = {}
    ): Promise<
        FirestoreResult<
            ExplainResults<AggregateQuerySnapshot<S, AppModelType, DbModelType>>
        >
    > {
        return firestoreResult(async () => {
            return this.query.firestore._trace(
                'AggregateQuery.explain',
                async () => {
                    validateExplainOptions(options);
                    const result = await this.execute(
                        this.spec,
                        undefined,
                        options
                    );
                    const metrics = (
                        result as AggregateData & {
                            [aggregateMetrics]?: ExplainMetrics;
                        }
                    )[aggregateMetrics];
                    if (!metrics) {
                        throw new FirebaseEdgeError({
                            ...FirestoreErrorInfo.INVALID_RESPONSE,
                            message: 'No explain metrics returned.'
                        });
                    }
                    return {
                        metrics,
                        snapshot: options.analyze
                            ? new AggregateQuerySnapshot(
                                  this,
                                  result,
                                  (
                                      result as AggregateData & {
                                          [aggregateReadTime]?: Timestamp;
                                      }
                                  )[aggregateReadTime]
                              )
                            : null
                    };
                }
            );
        });
    }
    isEqual(other: unknown): boolean {
        return (
            other instanceof AggregateQuery &&
            this.query.isEqual(other.query) &&
            valueEquals(this.spec, other.spec)
        );
    }
    private readonly spec: S;
    /** @internal Use query.aggregate() or query.count(). */
    constructor(
        readonly query: Query<AppModelType, DbModelType>,
        spec: S,
        private readonly execute: (
            spec: S,
            transaction?: string,
            explain?: ExplainOptions
        ) => Promise<AggregateData>
    ) {
        const fields = Object.values(spec ?? {});
        if (
            !fields.length ||
            fields.length > 5 ||
            fields.some((field) => !(field instanceof AggregateField))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Aggregates require one to five AggregateField values.'
            });
        this.spec = { ...spec };
    }
    async get(): Promise<
        FirestoreResult<AggregateQuerySnapshot<S, AppModelType, DbModelType>>
    > {
        return firestoreResult(async () => {
            return this.query.firestore._trace(
                'AggregateQuery.get',
                async () => {
                    return this._get();
                }
            );
        });
    }
    /** @internal Transaction-bound aggregate reads. */
    async _get(
        transaction?: string
    ): Promise<AggregateQuerySnapshot<S, AppModelType, DbModelType>> {
        const result = await this.execute(
            this.spec,
            ...(transaction ? [transaction] : [])
        );
        return new AggregateQuerySnapshot(
            this,
            result,
            (result as AggregateData & { [aggregateReadTime]?: Timestamp })[
                aggregateReadTime
            ]
        );
    }
}

export class AggregateQuerySnapshot<
    S extends AggregateSpec = AggregateSpec,
    AppModelType = DocumentData,
    DbModelType extends DocumentData = DocumentData
> {
    isEqual(other: unknown): boolean {
        return (
            other instanceof AggregateQuerySnapshot &&
            this.query.isEqual(other.query) &&
            valueEquals(this.result, other.result)
        );
    }
    /** @internal Obtain from AggregateQuery.get(). */
    constructor(
        readonly query: AggregateQuery<S, AppModelType, DbModelType>,
        private readonly result: AggregateData,
        readonly readTime: Timestamp = Timestamp.now()
    ) {}
    data(): AggregateSpecData<S> {
        return { ...this.result } as AggregateSpecData<S>;
    }
}

export type AggregateType = 'count' | 'avg' | 'sum';
export type AggregateFieldType =
    | AggregateField<number>
    | AggregateField<number | null>;
export type AggregateSpecData<S extends AggregateSpec> = {
    [K in keyof S]: S[K] extends AggregateField<infer T> ? T : never;
};
