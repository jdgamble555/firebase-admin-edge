import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { VectorValue } from './vector-value.js';
import { valueEquals } from './value-equality.js';
export type TransformKind =
    | 'serverTimestamp'
    | 'delete'
    | 'increment'
    | 'minimum'
    | 'maximum'
    | 'arrayUnion'
    | 'arrayRemove';
export class FieldValue {
    static vector(values: number[] = []): VectorValue {
        return new VectorValue(values);
    }
    isEqual(other: unknown): boolean {
        return (
            other instanceof FieldValue &&
            this.kind === other.kind &&
            valueEquals(this.operands, other.operands)
        );
    }
    private constructor(
        readonly kind: TransformKind,
        readonly operands: readonly unknown[] = []
    ) {}
    static serverTimestamp(): FieldValue {
        return new FieldValue('serverTimestamp');
    }
    static delete(): FieldValue {
        return new FieldValue('delete');
    }
    static increment(value: number): FieldValue {
        if (typeof value !== 'number' || !Number.isFinite(value))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Increment requires a finite number.'
            });
        return new FieldValue('increment', [value]);
    }
    static minimum(value: number): FieldValue {
        if (typeof value !== 'number')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a numeric transform operand.'
            });
        return new FieldValue('minimum', [value]);
    }
    static maximum(value: number): FieldValue {
        if (typeof value !== 'number')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a numeric transform operand.'
            });
        return new FieldValue('maximum', [value]);
    }
    static arrayUnion(...elements: unknown[]): FieldValue {
        return new FieldValue('arrayUnion', elements);
    }
    static arrayRemove(...elements: unknown[]): FieldValue {
        return new FieldValue('arrayRemove', elements);
    }
}
