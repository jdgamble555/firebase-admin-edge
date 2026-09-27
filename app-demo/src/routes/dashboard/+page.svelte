<script lang="ts">
	import type { PageProps } from './$types';

	let { data, form }: PageProps = $props();
	const providers = $derived(data.providers);
	let selectedProvider = $state<string | null>(null);
	let dialog: HTMLDialogElement;
	const action = $derived(
		selectedProvider && providers[selectedProvider] ? '?/removeProvider' : '?/addProvider'
	);
</script>

<svelte:head>
	<title>Connected providers</title>
</svelte:head>

<h1 class="text-2xl font-bold">Connected Providers</h1>

{#if form?.message}
	<p
		role={form.emailSent ? 'status' : 'alert'}
		class={form.emailSent ? 'text-green-800' : 'text-red-700'}
	>
		{form.message}
	</p>
{/if}

<div class="flex max-w-md flex-col gap-2">
	{#each Object.keys(providers) as provider (provider)}
		<label class="grid grid-cols-[1fr_auto] items-center gap-3">
			<span class="truncate">{provider}</span>
			<input
				class="justify-self-end"
				type="checkbox"
				name={provider}
				onchange={(event) => {
					event.currentTarget.checked = providers[provider];
					selectedProvider = provider;
					dialog.showModal();
				}}
				checked={providers[provider]}
			/>
		</label>
	{/each}
</div>

<dialog
	bind:this={dialog}
	aria-labelledby="provider-confirmation"
	class="m-auto rounded-md bg-white p-4 shadow backdrop:bg-black/30"
	onclick={(e) => {
		if (e.target === dialog) {
			dialog.close();
		}
	}}
>
	<p id="provider-confirmation" class="mb-4 text-slate-700">
		{selectedProvider && providers[selectedProvider] ? 'Disconnect' : 'Connect'}
		{selectedProvider}?
	</p>

	<div class="flex justify-end gap-2">
		<button
			type="button"
			class="rounded border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-100"
			onclick={() => dialog.close()}
		>
			Cancel
		</button>

		<form method="POST" {action}>
			<input type="hidden" name="provider" value={selectedProvider ?? ''} />
			<button
				type="submit"
				disabled={!selectedProvider}
				class="rounded bg-red-600 px-3 py-1.5 text-sm text-white hover:bg-red-700"
			>
				Yes, continue
			</button>
		</form>
	</div>
</dialog>

<section
	class="mx-4 w-[calc(100%-2rem)] max-w-sm rounded-lg border border-gray-200 bg-white p-6 sm:p-8"
	aria-labelledby="change-email"
>
	<h2 id="change-email" class="text-xl font-bold text-gray-900">Change email</h2>
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
	<a
		href="/reset-password"
		class="mt-5 block text-sm font-medium text-gray-600 underline underline-offset-4 hover:text-gray-900"
		>Reset password</a
	>
</section>
