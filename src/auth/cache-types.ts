export type SetCache = <T>(
    name: string,
    value: T,
    ttlMs?: number
) => Promise<void> | void;

export type GetCache = <T>(
    name: string
) => Promise<T | undefined> | T | undefined;

export type CacheConfig = {
    getCache: GetCache;
    setCache: SetCache;
};
