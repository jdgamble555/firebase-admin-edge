import { describe, expect, it, vi } from 'vitest';
import { load } from './+page.server';
import { aboutConverter } from './about-converter';

describe('about page', () => {
	it('returns the converted document', async () => {
		const about = { name: 'About', description: 'Our app' };
		const data = vi.fn().mockReturnValue(about);
		const get = vi.fn().mockResolvedValue({ error: null, data: { data } });
		const withConverter = vi.fn().mockReturnValue({ get });
		const doc = vi.fn().mockReturnValue({ withConverter });
		const event = { locals: { fbServer: { firestore: { doc } } } };

		const result = await load(event as unknown as Parameters<typeof load>[0]);

		expect(doc).toHaveBeenCalledWith('about/ZlNJrKd6LcATycPRmBPA');
		expect(withConverter).toHaveBeenCalledWith(aboutConverter);
		expect(data).toHaveBeenCalledOnce();
		expect(result).toEqual(about);
	});

	it('returns 404 for a missing document', async () => {
		const get = vi
			.fn()
			.mockResolvedValue({ error: null, data: { data: vi.fn().mockReturnValue(undefined) } });
		const withConverter = vi.fn().mockReturnValue({ get });
		const doc = vi.fn().mockReturnValue({ withConverter });
		const event = { locals: { fbServer: { firestore: { doc } } } };

		const result = load(event as unknown as Parameters<typeof load>[0]);

		await expect(result).rejects.toMatchObject({ status: 404 });
	});

	it.each(['read', 'conversion'])('propagates %s failures', async (stage) => {
		const failure = new Error('Document read or conversion failed');
		const data = vi.fn().mockImplementation(() => {
			throw failure;
		});
		const get =
			stage === 'read'
				? vi.fn().mockResolvedValue({ error: failure, data: null })
				: vi.fn().mockResolvedValue({ error: null, data: { data } });
		const withConverter = vi.fn().mockReturnValue({ get });
		const doc = vi.fn().mockReturnValue({ withConverter });
		const event = { locals: { fbServer: { firestore: { doc } } } };

		const result = load(event as unknown as Parameters<typeof load>[0]);

		await expect(result).rejects.toBe(failure);
	});
});
