<script lang="ts">
	import { resolve } from '$app/paths';
	import type { PageProps } from './$types';
	let { form }: PageProps = $props();
</script>

<svelte:head><title>Reset password</title></svelte:head>
<div
	class="mx-4 flex w-[calc(100%-2rem)] max-w-sm flex-col gap-5 rounded-lg border border-gray-200 bg-white p-6 sm:p-8"
>
	<div class="space-y-2 text-center">
		<h1 class="text-2xl font-bold tracking-tight text-gray-900">Reset password</h1>
		<p class="text-sm leading-relaxed text-gray-600">
			Enter your email and we’ll send you a reset link.
		</p>
	</div>
	{#if form?.message}
		<p
			role={form.sent ? 'status' : 'alert'}
			class={form.sent
				? 'rounded bg-green-50 p-3 text-sm text-green-800'
				: 'rounded bg-red-50 p-3 text-sm text-red-800'}
		>
			{form.message}
		</p>
	{/if}
	<form method="POST" class="flex flex-col gap-3">
		<label for="email" class="text-sm font-medium text-gray-800">Email address</label>
		<input
			id="email"
			name="email"
			type="email"
			autocomplete="email"
			placeholder="you@example.com"
			required
			class="w-full rounded border border-gray-300 px-3 py-2.5 text-sm focus:outline-2 focus:outline-blue-600"
		/>
		<button
			type="submit"
			class="w-full cursor-pointer rounded bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-700"
			>Send reset link</button
		>
	</form>
	<a
		href={resolve('/login')}
		class="text-center text-sm font-medium text-gray-600 underline underline-offset-4 hover:text-gray-900"
		>Back to sign in</a
	>
</div>
