import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { Timestamp } from './timestamp.js';
import { valueEquals } from './value-equality.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { DocumentReference } from './document-reference.js';
import { FieldPath } from './field-path.js';
import { validateFieldPath } from './query-request.js';
import { decodeValue, type FirestoreValue } from './firestore-document.js';
import {
    decodeFields,
    type DocumentData,
    type FirestoreDocument
} from './firestore-document.js';

/** A document read result, including a result for a missing document. */
export class DocumentSnapshot<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> {
    readonly id: string;
    readonly exists: boolean;
    readonly readTime: Timestamp;
    get createTime(): Timestamp | undefined {
        return this.document?.createTime
            ? Timestamp.fromString(this.document.createTime)
            : undefined;
    }
    get updateTime(): Timestamp | undefined {
        return this.document?.updateTime
            ? Timestamp.fromString(this.document.updateTime)
            : undefined;
    }
    isEqual(other: unknown): boolean {
        return (
            other instanceof DocumentSnapshot &&
            this.ref.isEqual(other.ref) &&
            this.exists === other.exists &&
            valueEquals(
                this.document?.fields ?? {},
                other.document?.fields ?? {}
            )
        );
    }

    /** @internal Obtain snapshots from DocumentReference.get(). */
    constructor(
        readonly ref: DocumentReference<T, DbModelType>,
        private readonly document: FirestoreDocument | undefined,
        readTime = Timestamp.now()
    ) {
        this.id = ref.id;
        this.exists = document !== undefined && !document.missing;
        this.readTime = document?.readTime
            ? Timestamp.fromString(document.readTime)
            : readTime;
    }
    /** @internal Preserve raw fields and nanosecond timestamps for bundles. */
    _bundleDocument(): FirestoreDocument | undefined {
        if (!this.exists || !this.document) return undefined;
        const { readTime: _, ...document } = this.document;
        return structuredClone({
            ...document,
            name: this.ref.firestore._documentName(this.ref.path)
        });
    }

    data(): T | undefined {
        if (!this.exists || this.document === undefined) return undefined;
        if (!this.ref.converter)
            return decodeFields(this.document.fields, this.ref.firestore) as T;
        const raw = new QueryDocumentSnapshot(
            this.ref.withConverter(null),
            this.document
        );
        return this.ref.converter.fromFirestore(raw);
    }

    get(fieldPath: string | FieldPath): unknown {
        const value = this._getValue(fieldPath);
        if (value === undefined) return undefined;
        return decodeValue(value, this.ref.firestore);
    }

    /** @internal Snapshot cursors use stored values, not converted application data. */
    _getValue(fieldPath: string | FieldPath): FirestoreValue | undefined {
        if (!(fieldPath instanceof FieldPath)) validateFieldPath(fieldPath);
        const segments =
            fieldPath instanceof FieldPath
                ? fieldPath.segments
                : fieldPath.split('.');
        let fields = this.document?.fields;
        for (let index = 0; index < segments.length; index++) {
            const segment = segments[index]!;
            if (!fields || !Object.hasOwn(fields, segment)) return undefined;
            const value = fields[segment]!;
            if (index === segments.length - 1) return value;
            if (!('mapValue' in value)) return undefined;
            fields = value.mapValue.fields;
        }
        return undefined;
    }
}

/** A query result always represents an existing document. */
export class QueryDocumentSnapshot<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> extends DocumentSnapshot<T, DbModelType> {
    override readonly exists = true as const;
    constructor(
        ref: DocumentReference<T, DbModelType>,
        document: FirestoreDocument
    ) {
        if (!document || document.missing)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message:
                    'A query document snapshot requires an existing document.'
            });
        super(ref, document);
    }
    override data(): T {
        return super.data()!;
    }
}
