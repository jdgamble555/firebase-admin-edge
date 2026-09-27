import { FirebaseEdgeError } from '../auth/errors.js';

it('wraps JSON syntax errors with a Firestore code and the original cause', async () => {
    const iterator = readJsonArray(new Response('[{"n":}]').body!);
    await expect(iterator.next()).rejects.toMatchObject({
        name: 'FirebaseEdgeError',
        code: 'firestore/internal',
        cause: expect.any(SyntaxError)
    });
});
import { expect, it, vi } from 'vitest';
import { readJsonArray } from './json-stream.js';

it('parses every byte boundary, nested arrays, escapes and multibyte text', async () => {
    const values = [
        { text: 'héllo 😀 " \\ } ]', nested: [{ n: 1 }] },
        { empty: {} }
    ];
    const bytes = new TextEncoder().encode(JSON.stringify(values));
    const body = new ReadableStream<Uint8Array>({
        start(controller) {
            for (const byte of bytes)
                controller.enqueue(new Uint8Array([byte]));
            controller.close();
        }
    });
    const rows: unknown[] = [];
    for await (const row of readJsonArray(body)) rows.push(row);
    expect(rows).toEqual(values);
    expect(body.locked).toBe(false);
});

it('yields a document before the entire response arrives and cancels on early return', async () => {
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({
        start(controller) {
            controller.enqueue(new TextEncoder().encode('[{"n":1},'));
        },
        cancel
    });
    const iterator = readJsonArray(body);
    const first = await iterator.next();
    expect(first.value).toEqual({ n: 1 });
    await iterator.return(undefined);
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(body.locked).toBe(false);
});

it.each([
    '',
    '{}',
    '[',
    '[{}',
    '[{},]',
    '[{}]x',
    '[true]',
    '[{"n":}]',
    '[{"text":"unfinished\\',
    '[{} {}]'
])('rejects malformed or truncated stream %s', async (text) => {
    const body = new Response(text).body!;
    const consume = async () => {
        for await (const _row of readJsonArray(body)) {
            /* drain */
        }
    };
    await expect(consume()).rejects.toThrow(FirebaseEdgeError);
    expect(body.locked).toBe(false);
});

it('yields objects lazily even when malformed trailing data shares the chunk', async () => {
    const body = new Response('[{"n":1},{"n":2}]invalid').body!;
    const iterator = readJsonArray(body);
    const first = await iterator.next();
    expect(first.value).toEqual({ n: 1 });
    const second = await iterator.next();
    expect(second.value).toEqual({ n: 2 });
    await expect(iterator.next()).rejects.toThrow(
        'Invalid Firestore streaming JSON response.'
    );
    expect(body.locked).toBe(false);
});

it('preserves parsing errors and releases the reader when cancellation fails', async () => {
    const cancel = vi.fn().mockRejectedValue(new Error('cancel failed'));
    const body = new ReadableStream<Uint8Array>({
        start(controller) {
            controller.enqueue(new TextEncoder().encode('[true]'));
        },
        cancel
    });
    await expect(readJsonArray(body).next()).rejects.toThrow(
        'Invalid Firestore streaming JSON response.'
    );
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(body.locked).toBe(false);
});

it('accepts empty arrays and surfaces reader failures', async () => {
    const values: unknown[] = [];
    for await (const row of readJsonArray(new Response(' [] ').body!))
        values.push(row);
    expect(values).toEqual([]);
    const body = new ReadableStream<Uint8Array>({
        start(controller) {
            controller.error(new Error('broken'));
        }
    });
    await expect(readJsonArray(body).next()).rejects.toThrow('broken');
});
