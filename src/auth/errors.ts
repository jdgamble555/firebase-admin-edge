// Error classes - https://medium.com/with-orus/the-5-commandments-of-clean-error-handling-in-typescript-93a9cbdf1af5

interface ErrorInfo {
    message: string;
    code?: string;
}

export function ensureError(value: unknown): Error {
    if (value instanceof Error) return value;

    if (value instanceof FirebaseEdgeError) return value;

    let stringified = '[Unable to stringify the thrown value]';
    try {
        stringified = JSON.stringify(value);
    } catch {}

    const error = new Error(
        `This value was thrown as is, not through an Error: ${stringified}`
    );
    return error;
}

type Jsonable =
    | string
    | number
    | boolean
    | null
    | undefined
    | readonly Jsonable[]
    | { readonly [key: string]: Jsonable }
    | { toJSON(): Jsonable };

export class FirebaseEdgeError extends Error {
    public readonly context?: Jsonable;
    public readonly code?: string;

    constructor(
        { message, code }: ErrorInfo,
        options: { cause?: Error; context?: Jsonable } = {}
    ) {
        const { cause, context } = options;

        super(message, { cause });
        this.name = this.constructor.name;

        this.context = context;
        this.code = code;

        Object.setPrototypeOf(this, FirebaseEdgeError.prototype);
    }
}

// Re-export error codes for backward compatibility
export * from './auth-error-codes.js';
