import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
/** An instant with nanosecond precision, in Firestore's supported date range. */
export class Timestamp {
    constructor(
        readonly seconds: number,
        readonly nanoseconds: number
    ) {
        if (
            !Number.isInteger(seconds) ||
            seconds < -62135596800 ||
            seconds > 253402300799
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Timestamp seconds are out of range.'
            });
        if (
            !Number.isInteger(nanoseconds) ||
            nanoseconds < 0 ||
            nanoseconds >= 1e9
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Timestamp nanoseconds are out of range.'
            });
    }
    static fromInstant(instant: {
        readonly epochNanoseconds: bigint;
    }): Timestamp {
        if (!instant || typeof instant.epochNanoseconds !== 'bigint')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Expected a Temporal instant.'
            });
        const nanos = instant.epochNanoseconds;
        const remainder = ((nanos % 1000000000n) + 1000000000n) % 1000000000n;
        return new Timestamp(
            Number((nanos - remainder) / 1000000000n),
            Number(remainder)
        );
    }
    toInstant(): { readonly epochNanoseconds: bigint; toString(): string } {
        const temporal = (
            globalThis as unknown as {
                Temporal?: {
                    Instant: new (nanos: bigint) => {
                        readonly epochNanoseconds: bigint;
                        toString(): string;
                    };
                };
            }
        ).Temporal;
        if (!temporal?.Instant)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message:
                    'Temporal.Instant is unavailable in this runtime. Provide a Temporal polyfill to use toInstant().'
            });
        return new temporal.Instant(
            BigInt(this.seconds) * 1000000000n + BigInt(this.nanoseconds)
        );
    }
    static now(): Timestamp {
        return Timestamp.fromMillis(Date.now());
    }
    static fromDate(date: Date): Timestamp {
        return Timestamp.fromMillis(date.getTime());
    }
    static fromMillis(milliseconds: number): Timestamp {
        if (!Number.isFinite(milliseconds))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid timestamp milliseconds.'
            });
        const seconds = Math.floor(milliseconds / 1000);
        return new Timestamp(
            seconds,
            Math.floor((milliseconds - seconds * 1000) * 1e6)
        );
    }
    /** @internal Parse a Firestore RFC3339 UTC timestamp without losing nanoseconds. */
    static fromString(value: string): Timestamp {
        const match =
            /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(
                value
            );
        if (!match)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid Firestore timestamp.'
            });
        const parsed = new Date(`${match[1]}Z`);
        if (
            !Number.isFinite(parsed.getTime()) ||
            parsed.toISOString().slice(0, 19) !== match[1]
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid Firestore timestamp.'
            });
        return new Timestamp(
            Date.parse(`${match[1]}Z`) / 1000,
            Number((match[2] ?? '').padEnd(9, '0'))
        );
    }
    toDate(): Date {
        return new Date(
            this.seconds * 1000 + Math.round(this.nanoseconds / 1e6)
        );
    }
    toMillis(): number {
        return this.seconds * 1000 + Math.floor(this.nanoseconds / 1e6);
    }
    isEqual(other: Timestamp): boolean {
        return (
            other instanceof Timestamp &&
            this.seconds === other.seconds &&
            this.nanoseconds === other.nanoseconds
        );
    }
    toJSON(): { seconds: number; nanoseconds: number } {
        return { seconds: this.seconds, nanoseconds: this.nanoseconds };
    }
    valueOf(): string {
        return `${String(this.seconds + 62135596800).padStart(12, '0')}.${String(this.nanoseconds).padStart(9, '0')}`;
    }
    /** @internal REST representation. */
    toString(): string {
        return `${new Date(this.seconds * 1000).toISOString().slice(0, 19)}.${String(this.nanoseconds).padStart(9, '0')}Z`;
    }
}
