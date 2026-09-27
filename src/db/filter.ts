import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { FieldPath } from './field-path.js';
import {
    encodeValue,
    OPERATORS,
    validateFieldPath,
    type WhereFilterOp
} from './query-request.js';
import type { FirestoreValue } from './firestore-document.js';

export type FilterNode =
    | { field: string; operator: WhereFilterOp; value: FirestoreValue }
    | { op: 'AND' | 'OR'; filters: FilterNode[] };
export class Filter {
    private constructor(readonly node: FilterNode) {}
    static where(
        field: string | FieldPath,
        operator: WhereFilterOp,
        value: unknown
    ): Filter {
        const path = field instanceof FieldPath ? field.toString() : field;
        if (!(field instanceof FieldPath)) validateFieldPath(path);
        if (!Object.hasOwn(OPERATORS, operator))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid Firestore query operator.'
            });
        if (
            ['in', 'not-in', 'array-contains-any'].includes(operator) &&
            (!Array.isArray(value) ||
                !value.length ||
                value.length > (operator === 'not-in' ? 10 : 30))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message:
                    'Query operator requires a non-empty array within the Firestore value limit.'
            });
        return new Filter({ field: path, operator, value: encodeValue(value) });
    }
    static and(...filters: Filter[]): Filter {
        return Filter.combine('AND', filters);
    }
    static or(...filters: Filter[]): Filter {
        return Filter.combine('OR', filters);
    }
    private static combine(op: 'AND' | 'OR', filters: Filter[]): Filter {
        if (
            !filters.length ||
            filters.some((filter) => !(filter instanceof Filter))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Composite filters require Filter instances.'
            });
        return new Filter({
            op,
            filters: filters.map((filter) => filter.node)
        });
    }
}
