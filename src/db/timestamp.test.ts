import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it, vi } from 'vitest';
import { Timestamp } from './timestamp.js';
it('round-trips dates, milliseconds, negative times, nanoseconds and JSON', () => {
    const time = new Timestamp(-1, 999999999);
    expect(time.toMillis()).toBe(-1);
    expect(time.toString()).toBe('1969-12-31T23:59:59.999999999Z');
    expect(Timestamp.fromString(time.toString()).isEqual(time)).toBe(true);
    expect(time.toJSON()).toEqual({ seconds: -1, nanoseconds: 999999999 });
    expect(Timestamp.fromMillis(-1).toDate().getTime()).toBe(-1);
    expect(Timestamp.fromDate(new Date(1234)).toMillis()).toBe(1234);
    expect(new Timestamp(0, 1) > new Timestamp(-1, 999999999)).toBe(true);
    expect(time.isEqual(new Timestamp(-1, 1))).toBe(false);
    expect(time.isEqual(null as never)).toBe(false);
    const now = vi.spyOn(Date, 'now').mockReturnValue(42);
    expect(Timestamp.now().toMillis()).toBe(42);
    now.mockRestore();
});
it('guards ranges and invalid input', () => {
    for (const seconds of [NaN, 1.5, -62135596801, 253402300800])
        expect(() => new Timestamp(seconds, 0)).toThrow(FirebaseEdgeError);
    for (const nanos of [-1, 1e9, 0.5, NaN])
        expect(() => new Timestamp(0, nanos)).toThrow(FirebaseEdgeError);
    expect(() => Timestamp.fromMillis(Infinity)).toThrow(FirebaseEdgeError);
    expect(() => Timestamp.fromDate(new Date('bad'))).toThrow(
        FirebaseEdgeError
    );
    expect(() => Timestamp.fromString('bad')).toThrow(FirebaseEdgeError);
    expect(() => Timestamp.fromString('2026-02-30T00:00:00Z')).toThrow(
        FirebaseEdgeError
    );
    expect(Timestamp.fromString('0001-01-01T00:00:00Z').seconds).toBe(
        -62135596800
    );
    expect(
        Timestamp.fromString('9999-12-31T23:59:59.999999999Z').nanoseconds
    ).toBe(999999999);
});

it('matches server SDK millisecond flooring and date rounding', () => {
    expect(new Timestamp(0, 600000).toMillis()).toBe(0);
    expect(new Timestamp(0, 600000).toDate().getTime()).toBe(1);
    expect(new Timestamp(-1, 999600000).toMillis()).toBe(-1);
    expect(new Timestamp(-1, 999600000).toDate().getTime()).toBe(0);
});
it('converts Temporal instants exactly and guards missing runtime support', () => {
    expect(Timestamp.fromInstant({ epochNanoseconds: -1n })).toEqual(
        new Timestamp(-1, 999999999)
    );
    expect(() => Timestamp.fromInstant(null as never)).toThrow(
        FirebaseEdgeError
    );
    expect(() =>
        Timestamp.fromInstant({ epochNanoseconds: 253402300800000000000n })
    ).toThrow(FirebaseEdgeError);
    vi.stubGlobal('Temporal', undefined);
    try {
        expect(() => Timestamp.now().toInstant()).toThrow(
            'Temporal.Instant is unavailable'
        );
    } finally {
        vi.unstubAllGlobals();
    }
    class Instant {
        constructor(readonly epochNanoseconds: bigint) {}
    }
    vi.stubGlobal('Temporal', { Instant });
    try {
        expect(new Timestamp(-1, 999999999).toInstant().epochNanoseconds).toBe(
            -1n
        );
    } finally {
        vi.unstubAllGlobals();
    }
});
