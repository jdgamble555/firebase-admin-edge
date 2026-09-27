import { page } from 'vitest/browser';
import { expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import EmailSignIn from './+page.svelte';

it('requires an explicit POST confirmation without asking for carried email', async () => {
	const { container } = render(EmailSignIn, {
		data: { user: null, hasLink: true, actionMode: 'signIn' },
		form: null,
		params: {}
	});
	await expect.element(page.getByRole('button', { name: 'Continue signing in' })).toBeVisible();
	expect(container.querySelector('form')?.method).toBe('post');
	expect(container.querySelector('input[name=email]')).toBeNull();
});

it('asks for email only when completion requires it', async () => {
	render(EmailSignIn, {
		data: { user: null, hasLink: true, actionMode: 'signIn' },
		form: { message: 'Enter your email', needsEmail: true, complete: false },
		params: {}
	});
	await expect.element(page.getByLabelText('Email address this link was sent to')).toBeVisible();
	await expect.element(page.getByRole('alert')).toHaveTextContent('Enter your email');
});

it.each(['resetPassword', 'verifyAndChangeEmail'] as const)(
	'renders the %s form',
	async (actionMode) => {
		const { container } = render(EmailSignIn, {
			data: { user: null, hasLink: true, actionMode },
			form: null,
			params: {}
		});
		await expect
			.element(
				page.getByRole('button', {
					name: actionMode === 'resetPassword' ? 'Reset password' : 'Confirm email'
				})
			)
			.toBeVisible();
		expect(container.querySelector('form')?.method).toBe('post');
		expect(container.querySelectorAll('input[type=password]').length).toBe(
			actionMode === 'resetPassword' ? 2 : 0
		);
	}
);
it('shows success without offering to reuse the code', async () => {
	const { container } = render(EmailSignIn, {
		data: { user: null, hasLink: true, actionMode: 'resetPassword' },
		form: { message: 'Password reset.', complete: true, needsEmail: false },
		params: {}
	});
	await expect.element(page.getByRole('status')).toHaveTextContent('Password reset.');
	expect(container.querySelector('form')).toBeNull();
});
