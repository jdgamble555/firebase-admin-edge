import { FirebaseEdgeError } from './errors.js';

export interface AuthEmulatorOptions {
    /** Host and port without a protocol. Undefined reads FIREBASE_AUTH_EMULATOR_HOST; null forces production. */
    emulatorHost?: string | null;
}

/** Resolve once per auth instance, including in edge runtimes without process.env. @internal */
export function resolveAuthEmulatorHost(host?: string | null): string | null {
    if (host === null) return null;
    const environment = (
        globalThis as typeof globalThis & {
            process?: { env?: Record<string, string | undefined> };
        }
    ).process?.env?.FIREBASE_AUTH_EMULATOR_HOST;
    const value = host === undefined ? environment || null : host;
    if (value === null) return null;
    if (
        typeof value !== 'string' ||
        !/^(\[[\da-fA-F:]+\]|[a-zA-Z0-9.-]+):\d+$/.test(value)
    )
        throw new FirebaseEdgeError({
            code: 'auth/invalid-emulator-host',
            message:
                'Auth emulator host must be host:port without a protocol, path, or credentials.'
        });
    const port = Number(value.slice(value.lastIndexOf(':') + 1));
    if (port < 1 || port > 65535 || !URL.canParse(`http://${value}`))
        throw new FirebaseEdgeError({
            code: 'auth/invalid-emulator-host',
            message:
                'Auth emulator host must include a valid hostname and port (1–65535).'
        });
    return value;
}
