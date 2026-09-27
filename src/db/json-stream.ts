import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError, ensureError } from '../auth/errors.js';
/** Parse a REST streaming JSON array one object at a time, across arbitrary chunks. */
export async function* readJsonArray(
    body: ReadableStream<Uint8Array>
): AsyncGenerator<unknown> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    const parser = new JsonArrayParser();
    let finished = false;
    try {
        for (;;) {
            const chunk = await reader.read();
            const text = decoder.decode(chunk.value, { stream: !chunk.done });
            yield* parser.read(text);
            if (!chunk.done) continue;
            finished = true;
            parser.finish();
            return;
        }
    } finally {
        if (!finished) {
            try {
                await reader.cancel();
            } catch {
                /* Preserve the original stream error. */
            }
        }
        reader.releaseLock();
    }
}

/** Tracks array framing separately from the stream's lifetime. */
class JsonArrayParser {
    private phase:
        | 'start'
        | 'first'
        | 'value'
        | 'object'
        | 'separator'
        | 'end' = 'start';
    private current = '';
    private depth = 0;
    private quoted = false;
    private escaped = false;

    *read(text: string): Generator<unknown> {
        for (const character of text) {
            if (this.phase === 'object') {
                if (!this.appendObjectCharacter(character)) continue;
                let value: unknown;
                try {
                    value = JSON.parse(this.current);
                } catch (cause) {
                    throw new FirebaseEdgeError(
                        FirestoreErrorInfo.INVALID_RESPONSE,
                        { cause: ensureError(cause) }
                    );
                }
                this.current = '';
                this.phase = 'separator';
                yield value;
                continue;
            }
            if (/\s/.test(character)) continue;
            if (this.phase === 'start' && character === '[') {
                this.phase = 'first';
                continue;
            }
            if (
                (this.phase === 'first' || this.phase === 'value') &&
                character === '{'
            ) {
                this.phase = 'object';
                this.current = '{';
                this.depth = 1;
                continue;
            }
            // An empty array is valid, but a closing bracket after a comma isn't.
            if (
                (this.phase === 'first' || this.phase === 'separator') &&
                character === ']'
            ) {
                this.phase = 'end';
                continue;
            }
            if (this.phase === 'separator' && character === ',') {
                this.phase = 'value';
                continue;
            }
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid Firestore streaming JSON response.'
            });
        }
    }

    finish(): void {
        if (this.phase !== 'end')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Truncated Firestore streaming JSON response.'
            });
    }

    /** Find object boundaries; JSON.parse validates the completed object. */
    private appendObjectCharacter(character: string): boolean {
        this.current += character;
        if (this.escaped) {
            this.escaped = false;
            return false;
        }
        if (this.quoted && character === '\\') {
            this.escaped = true;
            return false;
        }
        if (character === '"') {
            this.quoted = !this.quoted;
            return false;
        }
        if (this.quoted) return false;
        if (character === '{' || character === '[') this.depth++;
        if (character === '}' || character === ']') this.depth--;
        return this.depth === 0;
    }
}
