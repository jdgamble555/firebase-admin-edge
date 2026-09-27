import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError, ensureError } from '../auth/errors.js';
/** Edge-compatible byte values; no Node Buffer dependency. */
export class Bytes {
    private constructor(private readonly value: Uint8Array) {}
    static fromBase64String(value: string): Bytes {
        if (typeof value !== 'string')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected base64 text.'
            });
        try {
            return new Bytes(
                Uint8Array.from(atob(value), (character) =>
                    character.charCodeAt(0)
                )
            );
        } catch (cause) {
            throw new FirebaseEdgeError(
                {
                    ...FirestoreErrorInfo.INVALID_ARGUMENT,
                    message: 'Expected base64 text.'
                },
                { cause: ensureError(cause) }
            );
        }
    }
    static fromUint8Array(value: Uint8Array): Bytes {
        if (!(value instanceof Uint8Array)) {
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected Uint8Array.'
            });
        }

        return new Bytes(new Uint8Array(value));
    }
    toBase64(): string {
        return btoa(
            Array.from(this.value, (byte) => String.fromCharCode(byte)).join('')
        );
    }
    toUint8Array(): Uint8Array {
        return this.value.slice();
    }
    isEqual(other: Bytes): boolean {
        return (
            other instanceof Bytes &&
            this.value.length === other.value.length &&
            this.value.every((byte, index) => byte === other.value[index])
        );
    }
    toString(): string {
        return `Bytes(base64: ${this.toBase64()})`;
    }
}
