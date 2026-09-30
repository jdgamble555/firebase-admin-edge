<script lang="ts">
	import { resolve } from '$app/paths';
	import type { PageProps } from './$types';
	let { data, form }: PageProps = $props();
	const isReset = $derived(data.actionMode === 'resetPassword');
	const isEmailAction = $derived(
		['verifyAndChangeEmail', 'verifyEmail', 'recoverEmail'].includes(data.actionMode ?? '')
	);
	const title = $derived(
		isReset ? 'Reset your password' : isEmailAction ? 'Confirm your email' : 'Complete sign-in'
	);
</script>

<svelte:head>
	<title>{title}</title>
	<meta name="referrer" content="no-referrer" />
</svelte:head>

<div
	class="mx-4 flex w-[calc(100%-2rem)] max-w-sm flex-col gap-5 rounded-lg border border-gray-200 bg-white p-6 sm:p-8"
>
	<h1 class="text-center text-2xl font-bold tracking-tight text-gray-900">{title}</h1>
	{#if form?.message}<p
			role={form.complete ? 'status' : 'alert'}
			class={form.complete
				? 'rounded bg-green-50 p-3 text-sm leading-relaxed text-green-800'
				: 'rounded bg-red-50 p-3 text-sm leading-relaxed text-red-800'}
		>
			{form.message}
		</p>{/if}
	{#if form?.complete}
		<a
			href={resolve('/login')}
			class="text-center text-sm font-medium text-blue-700 underline underline-offset-4"
			>Back to sign in</a
		>
	{:else if data.hasLink}
		<p class="text-center text-sm leading-relaxed text-gray-600">
			{#if isReset}Choose a new password for your account.
			{:else if isEmailAction}Confirm this change only if you requested it.
			{:else}Continue if you requested this sign-in email. Do not use a link sent to you by someone
				else.{/if}
		</p>
		<form method="POST" class="flex flex-col gap-3">
			{#if isReset}
				<label for="password" class="text-sm font-medium text-gray-800">New password</label>
				<input
					id="password"
					name="password"
					type="password"
					autocomplete="new-password"
					required
					class="w-full rounded border border-gray-300 px-3 py-2.5 text-sm focus:outline-2 focus:outline-blue-600"
				/>
				<label for="confirmPassword" class="text-sm font-medium text-gray-800"
					>Confirm password</label
				>
				<input
					id="confirmPassword"
					name="confirmPassword"
					type="password"
					autocomplete="new-password"
					required
					class="w-full rounded border border-gray-300 px-3 py-2.5 text-sm focus:outline-2 focus:outline-blue-600"
				/>
			{/if}
			{#if form?.needsEmail}
				<label for="email" class="text-sm font-medium text-gray-800"
					>Email address this link was sent to</label
				>
				<input
					id="email"
					name="email"
					type="email"
					autocomplete="email"
					required
					placeholder="you@example.com"
					class="w-full rounded border border-gray-300 px-3 py-2.5 text-sm focus:border-blue-600 focus:outline-2 focus:outline-blue-600"
				/>
			{/if}
			<button
				type="submit"
				class="w-full cursor-pointer rounded bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-700"
				>{isReset
					? 'Reset password'
					: isEmailAction
						? 'Confirm email'
						: 'Continue signing in'}</button
			>
		</form>
	{:else}
		<p class="text-center text-sm leading-relaxed text-gray-600">
			Open the link in your email to continue.
		</p>
	{/if}
	{#if !form?.complete}
		<a
			href={resolve('/login')}
			class="text-center text-sm font-medium text-gray-600 underline underline-offset-4 hover:text-gray-900"
			>Back to sign in</a
		>
	{/if}
</div>
