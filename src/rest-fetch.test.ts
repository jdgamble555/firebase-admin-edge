import { describe, it, expect, vi, beforeEach } from 'vitest';
import { restFetch } from './rest-fetch.js';

describe('restFetch', () => {
    let mockFetch: ReturnType<typeof vi.fn<typeof fetch>>;

    beforeEach(() => {
        mockFetch = vi.fn<typeof fetch>();
        global.fetch = mockFetch;
    });

    it('should make GET request with default options', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: () => Promise.resolve({ success: true })
        } as Response);

        const result = await restFetch('https://api.example.com');

        expect(mockFetch).toHaveBeenCalledWith('https://api.example.com', {
            method: 'POST',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json'
            },
            body: undefined
        });

        expect(result).toEqual({ data: { success: true }, error: null });
    });

    it('should make GET request with query parameters', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: () => Promise.resolve({ data: 'test' })
        } as Response);

        await restFetch('https://api.example.com', {
            method: 'GET',
            params: { search: 'query', limit: '10' }
        });

        expect(mockFetch).toHaveBeenCalledWith(
            'https://api.example.com?search=query&limit=10',
            {
                method: 'GET',
                headers: {
                    Accept: '*/*',
                    'Content-Type': 'application/json'
                },
                body: undefined
            }
        );
    });

    it('should send JSON body with POST request', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: () => Promise.resolve({})
        } as Response);

        await restFetch('https://api.example.com', {
            method: 'POST',
            body: { name: 'test', value: 123 }
        });

        expect(mockFetch).toHaveBeenCalledWith('https://api.example.com', {
            method: 'POST',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name: 'test', value: 123 })
        });
    });

    it('should send form data when form option is true', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: () => Promise.resolve({})
        } as Response);

        await restFetch('https://api.example.com', {
            form: true,
            body: { username: 'test', password: 'secret' }
        });

        expect(mockFetch).toHaveBeenCalledWith('https://api.example.com', {
            method: 'POST',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: expect.any(URLSearchParams)
        });
    });

    it('should include bearer token in headers', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: () => Promise.resolve({})
        } as Response);

        await restFetch('https://api.example.com', {
            bearerToken: 'abc123'
        });

        expect(mockFetch).toHaveBeenCalledWith('https://api.example.com', {
            method: 'POST',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
                Authorization: 'Bearer abc123'
            },
            body: undefined
        });
    });

    it('should merge custom headers', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: () => Promise.resolve({})
        } as Response);

        await restFetch('https://api.example.com', {
            headers: { 'X-Custom': 'value' }
        });

        expect(mockFetch).toHaveBeenCalledWith('https://api.example.com', {
            method: 'POST',
            headers: {
                Accept: '*/*',
                'Content-Type': 'application/json',
                'X-Custom': 'value'
            },
            body: undefined
        });
    });

    it('should handle JSON error response', async () => {
        mockFetch.mockResolvedValue({
            ok: false,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: () => Promise.resolve({ message: 'Not found' })
        } as Response);

        const result = await restFetch('https://api.example.com');

        expect(result).toEqual({
            data: null,
            error: { message: 'Not found' }
        });
    });

    it('should handle text error response', async () => {
        mockFetch.mockResolvedValue({
            ok: false,
            headers: new Headers({ 'content-type': 'text/plain' }),
            text: () => Promise.resolve('Server error')
        } as Response);

        const result = await restFetch('https://api.example.com');

        expect(result).toEqual({
            data: null,
            error: 'Server error'
        });
    });

    it('should handle text success response', async () => {
        mockFetch.mockResolvedValue({
            ok: true,
            headers: new Headers({ 'content-type': 'text/plain' }),
            text: () => Promise.resolve('Success message')
        } as Response);

        const result = await restFetch('https://api.example.com');

        expect(result).toEqual({
            data: 'Success message',
            error: null
        });
    });

    it('should use custom fetch function', async () => {
        const customFetch = vi.fn().mockResolvedValue({
            ok: true,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: () => Promise.resolve({ custom: true })
        } as Response);

        await restFetch('https://api.example.com', {
            global: { fetch: customFetch }
        });

        expect(customFetch).toHaveBeenCalled();
        expect(mockFetch).not.toHaveBeenCalled();
    });
});
