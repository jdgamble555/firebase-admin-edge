const PRINT_URL = false;

export const restFetch = async <T, A>(
    url: string,
    options?: {
        body?: object;
        params?: Record<string, string>;
        form?: boolean;
        bearerToken?: string;
        method?: 'POST' | 'GET';
        global?: {
            fetch?: typeof fetch;
        };
        headers?: Record<string, string>;
    }
) => {
    const fetchFn = options?.global?.fetch ?? fetch;
    const form = options?.form ?? false;
    const bearerHeader = options?.bearerToken
        ? { Authorization: `Bearer ${options.bearerToken}` }
        : null;

    const query = options?.params
        ? '?' + new URLSearchParams(options.params)
        : '';

    const res = await fetchFn(url + query, {
        method: options?.method ?? 'POST',
        headers: {
            Accept: 'application/json',
            'Content-Type': form
                ? 'application/x-www-form-urlencoded'
                : 'application/json',
            ...bearerHeader,
            ...options?.headers
        },
        body: options?.body
            ? form
                ? new URLSearchParams(options.body as Record<string, string>)
                : JSON.stringify(options.body)
            : undefined
    });

    if (PRINT_URL) {
        console.log('restFetch', url + query);
    }

    if (res.headers.get('content-type')?.includes('application/json')) {
        // TODO - check ${res.status} ${res.statusText}

        if (!res.ok) {
            const error = (await res.json()) as A;

            return {
                data: null,
                error
            };
        }

        const data = (await res.json()) as T;

        return {
            data,
            error: null
        };
    }

    if (!res.ok) {
        const error = (await res.text()) as A;

        return {
            data: null,
            error
        };
    }

    const data = (await res.text()) as T;

    return {
        data,
        error: null
    };
};
