import { describe, expect, it, vi } from 'vitest';
import type { QueryDocumentSnapshot } from 'firebase-admin-edge';
import { aboutConverter } from './about-converter';

describe('aboutConverter', () => {
	it.each([
		{ name: 'About', description: 'Our app' },
		{ name: '', description: '' },
		{ name: '<strong>Name</strong>', description: 'First line\nSecond line' }
	])('converts stored fields: %j', (about) => {
		const get = vi.fn().mockImplementation((field: keyof typeof about) => about[field]);
		const snapshot = { get } as unknown as QueryDocumentSnapshot;

		const result = aboutConverter.fromFirestore(snapshot);

		expect(result).toEqual(about);
		expect(get).toHaveBeenCalledWith('name');
		expect(get).toHaveBeenCalledWith('description');
	});

	it.each(['name', 'description'] as const)('rejects invalid %s values', (field) => {
		for (const value of [undefined, null, 123, {}]) {
			const fields = { name: 'About', description: 'Our app', [field]: value };
			const snapshot = {
				get: vi.fn().mockImplementation((key: keyof typeof fields) => fields[key])
			} as unknown as QueryDocumentSnapshot;

			let failure: unknown;
			try {
				aboutConverter.fromFirestore(snapshot);
			} catch (error) {
				failure = error;
			}

			expect(failure).toMatchObject({
				status: 500,
				body: { message: `The about document must have a ${field} string.` }
			});
		}
	});

	it('writes only the model fields', () => {
		const model = { name: 'About', description: 'Our app', extra: 'Not persisted' };

		const result = aboutConverter.toFirestore(model);

		expect(result).toEqual({ name: 'About', description: 'Our app' });
	});
});
