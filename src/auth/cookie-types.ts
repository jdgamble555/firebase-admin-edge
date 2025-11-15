export interface StringifyOptions {
    encode?: (str: string) => string;
}

export type CookieOptions = Partial<{
    encode: (value: string) => string;
    maxAge: number;
    expires: Date;
    domain: string;
    httpOnly: boolean;
    secure: boolean;
    partitioned: boolean;
    priority: 'low' | 'medium' | 'high';
    sameSite: boolean | 'lax' | 'strict' | 'none';
}> & { path: string };

export type GetSession = (
    name: string,
) => Promise<string | null | undefined> | string | null | undefined;

export type SetSession = (
    name: string,
    value: string,
    options: CookieOptions,
) => Promise<void> | void;
