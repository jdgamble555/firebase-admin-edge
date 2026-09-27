import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
export class FieldPath {
    readonly segments: readonly string[];
    constructor(...fieldNames: string[]) {
        if (
            !fieldNames.length ||
            fieldNames.some((name) => typeof name !== 'string' || !name.length)
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'FieldPath requires non-empty field names.'
            });
        this.segments = Object.freeze([...fieldNames]);
    }
    static documentId(): FieldPath {
        return new FieldPath('__name__');
    }
    isEqual(other: FieldPath): boolean {
        return (
            other instanceof FieldPath &&
            this.segments.length === other.segments.length &&
            this.segments.every((segment, i) => segment === other.segments[i])
        );
    }
    toString(): string {
        return this.segments
            .map((segment) =>
                /^[A-Za-z_][A-Za-z_0-9]*$/.test(segment)
                    ? segment
                    : `\`${segment.replaceAll('\\', '\\\\').replaceAll('`', '\\`')}\``
            )
            .join('.');
    }
}

/** @internal Parse REST field paths, including escaped literal segments. */
export function parseFieldPath(path: string): string[] {
    const segments: string[] = [];
    let segment = '';
    let quoted = false;
    let escaped = false;
    for (const character of path) {
        if (escaped) {
            segment += character;
            escaped = false;
            continue;
        }
        if (quoted && character === '\\') {
            escaped = true;
            continue;
        }
        if (character === '`') {
            quoted = !quoted;
            continue;
        }
        if (character === '.' && !quoted) {
            segments.push(segment);
            segment = '';
            continue;
        }
        segment += character;
    }
    if (quoted || escaped || !segment || segments.some((value) => !value))
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Invalid field path.'
        });
    segments.push(segment);
    return segments;
}
