import { FirebaseEdgeError } from '../auth/errors.js';

const shifts = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const constants = Uint32Array.from({ length: 64 }, (_, index) =>
    Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000)
);

/** @internal Incremental MD5 for Storage integrity checks in runtimes without Node crypto. */
export class StorageMd5 {
    private state = new Uint32Array([
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    ]);
    private pending = new Uint8Array(64);
    private used = 0;
    private length = 0n;

    update(bytes: Uint8Array): void {
        if (!(bytes instanceof Uint8Array)) {
            throw new FirebaseEdgeError({
                code: 'storage/invalid-argument',
                message: 'MD5 input must contain bytes.'
            });
        }
        this.length += BigInt(bytes.byteLength);
        let offset = 0;
        if (this.used) {
            const count = Math.min(64 - this.used, bytes.length);
            this.pending.set(bytes.subarray(0, count), this.used);
            this.used += count;
            offset += count;
            if (this.used === 64) {
                this.block(this.pending);
                this.used = 0;
            }
        }
        while (offset + 64 <= bytes.length) {
            this.block(bytes.subarray(offset, offset + 64));
            offset += 64;
        }
        if (offset < bytes.length) {
            this.pending.set(bytes.subarray(offset), this.used);
            this.used += bytes.length - offset;
        }
    }

    digest(): string {
        const copy = new StorageMd5();
        copy.state.set(this.state);
        copy.pending.set(this.pending);
        copy.used = this.used;
        copy.length = this.length;
        const padding = new Uint8Array(
            this.used < 56 ? 64 - this.used : 128 - this.used
        );
        padding[0] = 0x80;
        new DataView(padding.buffer).setBigUint64(
            padding.length - 8,
            BigInt.asUintN(64, this.length * 8n),
            true
        );
        copy.update(padding);
        const output = new Uint8Array(16);
        const view = new DataView(output.buffer);
        for (let index = 0; index < 4; index++) {
            view.setUint32(index * 4, copy.state[index]!, true);
        }
        return btoa(String.fromCharCode(...output));
    }

    private block(bytes: Uint8Array): void {
        const words = new DataView(bytes.buffer, bytes.byteOffset, 64);
        let a = this.state[0]!;
        let b = this.state[1]!;
        let c = this.state[2]!;
        let d = this.state[3]!;
        for (let index = 0; index < 64; index++) {
            const round = index >>> 4;
            const mixed =
                round === 0
                    ? (b & c) | (~b & d)
                    : round === 1
                      ? (d & b) | (~d & c)
                      : round === 2
                        ? b ^ c ^ d
                        : c ^ (b | ~d);
            const word =
                round === 0
                    ? index
                    : round === 1
                      ? (5 * index + 1) % 16
                      : round === 2
                        ? (3 * index + 5) % 16
                        : (7 * index) % 16;
            const sum =
                (a +
                    mixed +
                    constants[index]! +
                    words.getUint32(word * 4, true)) >>>
                0;
            const shift = shifts[round * 4 + (index % 4)]!;
            const next = (b + ((sum << shift) | (sum >>> (32 - shift)))) >>> 0;
            a = d;
            d = c;
            c = b;
            b = next;
        }
        for (const [index, value] of [a, b, c, d].entries()) {
            this.state[index] = (this.state[index]! + value) >>> 0;
        }
    }
}
