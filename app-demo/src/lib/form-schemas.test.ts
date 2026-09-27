import { describe, expect, it } from 'vitest';
import { safeParse } from 'valibot';
import {
	emailSchema,
	callbackSchema,
	linkProviderSchema,
	unlinkProviderSchema
} from './form-schemas';

describe('form schemas', () => {
	it('trims email without changing its case', () => {
		const { success, output } = safeParse(emailSchema, ' User@example.com ');
		expect(success).toBe(true);
		expect(output).toBe('User@example.com');
	});
	it.each(['', ' ', 'invalid', null, new Blob(['email'])])('rejects invalid email %s', (input) => {
		const { success } = safeParse(emailSchema, input);
		expect(success).toBe(false);
	});
	it.each(['google.com', 'github.com'])('allows linking %s', (provider) => {
		const { success } = safeParse(linkProviderSchema, provider);
		expect(success).toBe(true);
	});
	it.each(['google.com', 'github.com', 'email'])('allows unlinking %s', (provider) => {
		const { success } = safeParse(unlinkProviderSchema, provider);
		expect(success).toBe(true);
	});
	it.each(['', 'unknown', null, new Blob()])('rejects unsupported providers %s', (provider) => {
		const { success: link } = safeParse(linkProviderSchema, provider);
		const { success: unlink } = safeParse(unlinkProviderSchema, provider);
		expect(link).toBe(false);
		expect(unlink).toBe(false);
	});
	it('defaults absent callback fields without requiring email for carried-email links', () => {
		const { output } = safeParse(callbackSchema, {});
		expect(output).toEqual({ email: '', password: '', confirmPassword: '' });
	});
	it('preserves password whitespace and leaves matching to core', () => {
		const { success, output } = safeParse(callbackSchema, {
			email: ' a@b.com ',
			password: ' password ',
			confirmPassword: 'other'
		});
		expect(success).toBe(true);
		expect(output).toEqual({ email: 'a@b.com', password: ' password ', confirmPassword: 'other' });
	});
	it.each(['email', 'password', 'confirmPassword'])('rejects file values in %s', (field) => {
		const { success } = safeParse(callbackSchema, { [field]: new Blob() });
		expect(success).toBe(false);
	});
});
