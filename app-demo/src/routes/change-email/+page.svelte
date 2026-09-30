<script lang="ts">
	import type { PageProps } from './$types';

	let { form }: PageProps = $props();
</script>

<svelte:head>
	<title>Change email</title>
</svelte:head>

{#if form?.message}
	<p
		role={form.emailSent ? 'status' : 'alert'}
		class={form.emailSent ? 'text-green-800' : 'text-red-700'}
	>
		{form.message}
	</p>
{/if}

<section
	class="mx-4 w-[calc(100%-2rem)] max-w-sm rounded-lg border border-gray-200 bg-white p-6 sm:p-8"
	aria-labelledby="change-email"
>
	<h1 id="change-email" class="text-xl font-bold text-gray-900">Change email</h1>
	<p class="mt-2 text-sm leading-relaxed text-gray-600">
		We’ll send a confirmation link to your new address. Your email stays the same until you confirm.
	</p>
	<form method="POST" action="?/changeEmail" class="mt-5 flex flex-col gap-3">
		<label for="new-email" class="text-sm font-medium text-gray-800">New email address</label>
		<input
			id="new-email"
			name="email"
			type="email"
			autocomplete="email"
			required
			placeholder="you@example.com"
			class="w-full rounded border border-gray-300 px-3 py-2.5 text-sm focus:outline-2 focus:outline-blue-600"
		/>
		<button
			type="submit"
			class="w-full cursor-pointer rounded bg-blue-700 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-700"
			>Send confirmation link</button
		>
	</form>
</section>
