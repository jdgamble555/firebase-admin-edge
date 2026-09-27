import { FirebaseEdgeError } from '../auth/errors.js';
import { Buffer } from 'node:buffer';

it('copies Buffer inputs and never exposes a mutable view of its stored bytes', () => {
    const input = Buffer.from([1, 2, 3]);
    const bytes = Bytes.fromUint8Array(input.subarray(1));
    input[1] = 9;
    expect(bytes.toBase64()).toBe('AgM=');

    const output = bytes.toUint8Array();
    output[0] = 8;
    expect(bytes.toUint8Array()).toEqual(new Uint8Array([2, 3]));
    expect(Buffer.isBuffer(output)).toBe(false);
});

it('wraps invalid base64 with a structured error and retains the decoder cause', () => {
    expect(() => Bytes.fromBase64String('!')).toThrow(
        expect.objectContaining({
            name: 'FirebaseEdgeError',
            code: 'firestore/invalid-argument',
            cause: expect.any(Error)
        })
    );
});
import { expect, it } from 'vitest';
import { Bytes } from './bytes.js';
it('round-trips base64 and copies byte arrays', () => {
    const input = new Uint8Array([0, 255]);
    const bytes = Bytes.fromUint8Array(input);
    input[0] = 10;
    expect(bytes.toBase64()).toBe('AP8=');
    expect(bytes.isEqual(Bytes.fromBase64String('AP8='))).toBe(true);
    expect(bytes.toString()).toBe('Bytes(base64: AP8=)');
    const copy = bytes.toUint8Array();
    copy[0] = 8;
    expect(bytes.toUint8Array()).toEqual(new Uint8Array([0, 255]));
    expect(bytes.isEqual(Bytes.fromBase64String(''))).toBe(false);
    expect(bytes.isEqual(null as never)).toBe(false);
    expect(() => Bytes.fromBase64String('!')).toThrow(FirebaseEdgeError);
    expect(() => Bytes.fromBase64String(null as never)).toThrow(
        FirebaseEdgeError
    );
    expect(() => Bytes.fromUint8Array([] as never)).toThrow(FirebaseEdgeError);
});
