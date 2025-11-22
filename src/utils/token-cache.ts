export class TokenCache {
    private store = new Map<string, { value: unknown; expires: number }>();

    constructor() {}

    set<T>(key: string, value: T, ttlMs = 3600 * 1000) {
        this.store.set(key, {
            value,
            expires: Date.now() + ttlMs
        });
    }

    get<T>(key: string): T | undefined {
        const entry = this.store.get(key);
        if (!entry) return undefined;

        if (Date.now() > entry.expires) {
            this.store.delete(key);
            return undefined;
        }

        return entry.value as T;
    }

    has(key: string): boolean {
        return this.get(key) !== undefined;
    }

    delete(key: string) {
        return this.store.delete(key);
    }
}
