import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import type { DocumentReference } from './document-reference.js';
import type { DocumentData, FirestoreValue } from './firestore-document.js';
import { FieldValue } from './field-value.js';
import { FieldPath, parseFieldPath } from './field-path.js';
import { Timestamp } from './timestamp.js';
import { encodeValue, validateFieldPath } from './query-request.js';

export interface SetOptions {
    merge?: boolean;
    mergeFields?: (string | FieldPath)[];
}
export interface Precondition {
    exists?: boolean;
    lastUpdateTime?: Timestamp;
}
export class WriteResult {
    constructor(readonly writeTime: Timestamp) {
        if (!(writeTime instanceof Timestamp))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a Timestamp.'
            });
    }
    isEqual(other: unknown): boolean {
        return (
            other instanceof WriteResult &&
            this.writeTime.isEqual(other.writeTime)
        );
    }
}
export type WriteOperation = {
    path: string;
    kind: 'create' | 'set' | 'update' | 'delete';
    fields?: Record<string, FirestoreValue>;
    mask?: string[];
    transforms?: Record<string, unknown>[];
    precondition?: { exists?: boolean; updateTime?: string };
};
/** @internal Normalize both Admin update overloads before write serialization. */
export function normalizeUpdateArguments(
    first: DocumentData | string | FieldPath,
    rest: unknown[]
): { data: DocumentData; precondition?: Precondition } {
    if (typeof first !== 'string' && !(first instanceof FieldPath)) {
        if (rest.length > 1)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Object updates accept only an optional precondition.'
            });
        return {
            data: first,
            precondition: rest[0] as Precondition | undefined
        };
    }
    const args: unknown[] = [first, ...rest];
    const precondition =
        args.length % 2 ? (args.pop() as Precondition) : undefined;
    if (
        !args.length ||
        (precondition !== undefined &&
            (!precondition ||
                typeof precondition !== 'object' ||
                Array.isArray(precondition) ||
                Object.keys(precondition).some(
                    (key) => !['exists', 'lastUpdateTime'].includes(key)
                )))
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message:
                'Updates require field/value pairs and an optional precondition.'
        });
    const entries: [string, unknown][] = [];
    const seen = new Set<string>();
    for (let index = 0; index < args.length; index += 2) {
        const field = args[index];
        if (!(field instanceof FieldPath)) validateFieldPath(field as string);
        const path =
            field instanceof FieldPath
                ? field.toString()
                : new FieldPath(...(field as string).split('.')).toString();
        if (seen.has(path))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Duplicate update field.'
            });
        seen.add(path);
        entries.push([path, args[index + 1]]);
    }
    return { data: Object.fromEntries(entries), precondition };
}

/** Validate and capture a write before it enters a queue. */
export function prepareWrite(
    ref: DocumentReference<any>,
    kind: WriteOperation['kind'],
    data?: DocumentData,
    options?: SetOptions,
    precondition?: Precondition
): WriteOperation {
    if (
        precondition !== undefined &&
        (!precondition ||
            typeof precondition !== 'object' ||
            Object.getPrototypeOf(precondition) !== Object.prototype ||
            Object.keys(precondition).some(
                (key) => !['exists', 'lastUpdateTime'].includes(key)
            ))
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Invalid write precondition.'
        });
    if (
        precondition?.exists !== undefined &&
        typeof precondition.exists !== 'boolean'
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Invalid exists precondition.'
        });
    if (
        precondition?.lastUpdateTime !== undefined &&
        !(precondition.lastUpdateTime instanceof Timestamp)
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Invalid update-time precondition.'
        });
    if (precondition?.exists !== undefined && precondition.lastUpdateTime)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Use only one precondition.'
        });
    const condition = precondition?.lastUpdateTime
        ? { updateTime: precondition.lastUpdateTime.toString() }
        : precondition?.exists !== undefined
          ? { exists: precondition.exists }
          : undefined;
    if (kind === 'delete')
        return { path: ref.path, kind, precondition: condition };
    if (!data || Object.getPrototypeOf(data) !== Object.prototype)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Write data must be a plain object.'
        });
    if (options?.merge !== undefined && typeof options.merge !== 'boolean')
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'merge must be a boolean.'
        });
    if (
        options?.mergeFields !== undefined &&
        (!Array.isArray(options.mergeFields) || options.merge !== undefined)
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Use merge or mergeFields, not both.'
        });
    if (kind === 'update' && !Object.keys(data).length)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Update requires at least one field.'
        });
    if (kind === 'update') {
        const paths = Object.keys(data);
        if (
            paths.some((path) =>
                paths.some(
                    (other) => other !== path && other.startsWith(`${path}.`)
                )
            )
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Conflicting update paths.'
            });
    }
    const fields: Record<string, FirestoreValue> = Object.create(null);
    const mask: string[] = [];
    const transforms: Record<string, unknown>[] = [];
    for (const [key, value] of Object.entries(data)) {
        if (!key)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Write field names must not be empty.'
            });
        const segments = kind === 'update' ? parseFieldPath(key) : [key];
        const fieldPath = new FieldPath(...segments).toString();
        const encoded = encodeWriteValue(
            value,
            fieldPath,
            kind === 'update' || !!options?.merge || !!options?.mergeFields,
            mask,
            transforms,
            new Set(),
            ref.firestore._ignoreUndefinedProperties
        );
        if (encoded === undefined) continue;
        let target = fields;
        for (const segment of segments.slice(0, -1)) {
            if (
                Object.hasOwn(target, segment) &&
                !('mapValue' in target[segment]!)
            )
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_ARGUMENT,
                    message: 'Conflicting update paths.'
                });
            target[segment] ??= { mapValue: { fields: Object.create(null) } };
            target = (
                target[segment] as {
                    mapValue: { fields: Record<string, FirestoreValue> };
                }
            ).mapValue.fields;
        }
        const last = segments.at(-1)!;
        if (Object.hasOwn(target, last))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Conflicting update paths.'
            });
        target[last] = encoded;
        // Update map values replace the supplied field, while set/merge merges leaf fields.
        if (kind === 'update') {
            for (let i = mask.length - 1; i >= 0; i--)
                if (mask[i]!.startsWith(`${fieldPath}.`)) mask.splice(i, 1);
            if (!(value instanceof FieldValue)) mask.push(fieldPath);
        }
    }
    let selected = [...new Set(mask)];
    if (options?.mergeFields) {
        selected = options.mergeFields.map((field) =>
            field instanceof FieldPath
                ? field.toString()
                : (validateFieldPath(field), field)
        );
        for (const field of selected)
            if (
                ![
                    ...mask,
                    ...transforms.map((t) => t.fieldPath as string)
                ].some((path) => path === field || path.startsWith(`${field}.`))
            )
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_ARGUMENT,
                    message: 'mergeFields contains a field absent from data.'
                });
        for (let i = transforms.length - 1; i >= 0; i--)
            if (
                !selected.some(
                    (field) =>
                        transforms[i]!.fieldPath === field ||
                        String(transforms[i]!.fieldPath).startsWith(`${field}.`)
                )
            )
                transforms.splice(i, 1);
    }
    return {
        path: ref.path,
        kind,
        fields,
        ...(kind === 'update' || options?.merge || options?.mergeFields
            ? {
                  mask: selected.filter(
                      (path) => !transforms.some((t) => t.fieldPath === path)
                  )
              }
            : {}),
        transforms,
        precondition:
            kind === 'create'
                ? { exists: false }
                : kind === 'update'
                  ? (condition ?? { exists: true })
                  : undefined
    };
}

function encodeWriteValue(
    value: unknown,
    path: string,
    allowDelete: boolean,
    mask: string[],
    transforms: Record<string, unknown>[],
    ancestors: Set<object>,
    ignoreUndefined = false
): FirestoreValue | undefined {
    if (value === undefined && ignoreUndefined) return undefined;
    if (value instanceof FieldValue) {
        if (value.kind === 'delete') {
            if (!allowDelete)
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_ARGUMENT,
                    message: 'FieldValue.delete requires update or merge.'
                });
            mask.push(path);
            return undefined;
        }
        const transform: Record<string, unknown> = { fieldPath: path };
        if (value.kind === 'serverTimestamp')
            transform.setToServerValue = 'REQUEST_TIME';
        if (['increment', 'minimum', 'maximum'].includes(value.kind))
            transform[value.kind] = encodeValue(value.operands[0]);
        if (value.kind === 'arrayUnion')
            transform.appendMissingElements = {
                values: value.operands.map((item) =>
                    encodeValue(item, new Set(), ignoreUndefined)
                )
            };
        if (value.kind === 'arrayRemove')
            transform.removeAllFromArray = {
                values: value.operands.map((item) =>
                    encodeValue(item, new Set(), ignoreUndefined)
                )
            };
        transforms.push(transform);
        return undefined;
    }
    if (
        value &&
        typeof value === 'object' &&
        Object.getPrototypeOf(value) === Object.prototype &&
        Object.keys(value).length
    ) {
        if (ancestors.has(value))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Circular write data.'
            });
        const next = new Set(ancestors).add(value);
        const fields: Record<string, FirestoreValue> = Object.create(null);
        for (const [key, item] of Object.entries(value)) {
            const encoded = encodeWriteValue(
                item,
                `${path}.${new FieldPath(key)}`,
                allowDelete,
                mask,
                transforms,
                next,
                ignoreUndefined
            );
            if (encoded !== undefined) fields[key] = encoded;
        }
        return { mapValue: { fields } };
    }
    mask.push(path);
    return encodeValue(value, ancestors, ignoreUndefined);
}
