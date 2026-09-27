import { FirebaseEdgeError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';

export class VectorValue {
    private readonly values: readonly number[];
    /** Use FieldValue.vector(). */
    constructor(values: number[]) {
        if (
            !Array.isArray(values) ||
            values.length > 2048 ||
            Array.from(values).some(
                (value) => typeof value !== 'number' || !Number.isFinite(value)
            )
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Vectors require at most 2048 finite numbers.'
            });
        this.values = Object.freeze([...values]);
    }
    toArray(): number[] {
        return [...this.values];
    }
    isEqual(other: unknown): boolean {
        return (
            other instanceof VectorValue &&
            this.values.length === other.values.length &&
            this.values.every((value, i) => Object.is(value, other.values[i]))
        );
    }
}
