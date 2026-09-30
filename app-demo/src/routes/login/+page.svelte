<script lang="ts">
	import LoginWithGithub from '$lib/components/login-with-github.svelte';
	import LoginWithGoogle from '$lib/components/login-with-google.svelte';
	import type { PageProps } from './$types';
	let { form }: PageProps = $props();
</script>

<svelte:head>
	<title>Sign in</title>
</svelte:head>

<div
	class="mx-4 w-[calc(100%-2rem)] max-w-sm rounded-lg border border-gray-200 bg-white p-6 sm:p-8"
>
	<div class="mb-6 space-y-2 text-center">
		<h1 class="text-2xl font-bold tracking-tight text-gray-900">Sign in</h1>
		<p class="text-sm text-gray-600">Choose how you’d like to sign in.</p>
	</div>
	<div class="flex flex-col gap-3">
		<LoginWithGoogle />
		<LoginWithGithub />
	</div>
	<div class="my-6 flex items-center gap-3" aria-hidden="true">
		<span class="h-px flex-1 bg-gray-200"></span>
		<span class="text-xs text-gray-500">or use email</span>
		<span class="h-px flex-1 bg-gray-200"></span>
	</div>
	<form method="POST" action="?/email" class="flex flex-col gap-3">
		<label for="email" class="text-sm font-medium text-gray-800">Email address</label>
		<input
			id="email"
			name="email"
			type="email"
			autocomplete="email"
			required
			placeholder="you@example.com"
			class="w-full rounded border border-gray-300 px-3 py-2.5 text-sm focus:border-blue-600 focus:outline-2 focus:outline-blue-600"
		/>
		<button
			type="submit"
			class="w-full cursor-pointer rounded bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-700"
			>Email me a sign-in link</button
		>
		<p class="text-center text-xs leading-relaxed text-gray-500">
			We’ll email you a sign-in link. No password needed.
		</p>
	</form>
	{#if form?.message}
		<p
			role={form.sent ? 'status' : 'alert'}
			class={form.sent
				? 'mt-5 rounded bg-green-50 p-3 text-sm leading-relaxed text-green-800'
				: 'mt-5 rounded bg-red-50 p-3 text-sm leading-relaxed text-red-800'}
		>
			{form.message}
		</p>
	{/if}
</div>
