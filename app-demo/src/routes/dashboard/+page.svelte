<script lang="ts">
	import { resolve } from '$app/paths';
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
	<p role="alert" class="text-red-700">{form.message}</p>
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
	{:else}
		<p class="text-sm text-gray-600">No providers are available to connect.</p>
	{/each}
</div>

<div class="flex items-center gap-4">
	<a
		href={resolve('/change-email')}
		class="font-medium text-gray-700 underline underline-offset-4 hover:text-blue-600"
	>
		Change Email
	</a>
	<a
		href={resolve('/reset-password')}
		class="font-medium text-gray-700 underline underline-offset-4 hover:text-blue-600"
	>
		Reset Password
	</a>
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
