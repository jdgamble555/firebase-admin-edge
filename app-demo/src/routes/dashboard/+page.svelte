<script lang="ts">
	import { page } from '$app/state';
	import type { PageData } from './$types';
	import { addProvider, removeProvider } from './action';

	const providers = $derived((page.data as PageData).providers);

	let selectedProvider = $state<string | null>(null);

	let dialog: HTMLDialogElement;
</script>

<h1 class="text-2xl font-bold">Connected Providers</h1>

<div class="flex max-w-md flex-col gap-2">
	{#each Object.keys(providers) as provider (provider)}
		<div class="grid grid-cols-[1fr_auto] items-center gap-3">
			<span class="truncate">{provider}</span>
			<input
				class="justify-self-end"
				type="checkbox"
				name={provider}
				onchange={() => {
					selectedProvider = provider;
					providers[provider] = !providers[provider];
					if (dialog.open) {
						dialog.close();
						return;
					}
					dialog.showModal();
				}}
				checked={providers[provider]}
			/>
		</div>
	{/each}
</div>

<dialog
	bind:this={dialog}
	class="m-auto rounded-md bg-white p-4 shadow backdrop:bg-black/30"
	onclick={(e) => {
		if (e.target === dialog) {
			dialog.close();
		}
	}}
>
	<p class="mb-4 text-slate-700">Are you sure you want to continue?</p>

	<div class="flex justify-end gap-2">
		<button
			type="button"
			class="rounded border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-100"
			onclick={() => dialog.close()}
		>
			Cancel
		</button>

		<form method="dialog">
			<button
				class="rounded bg-red-600 px-3 py-1.5 text-sm text-white hover:bg-red-700"
				onclick={async () => {
					if (selectedProvider) {
						const isAdd = providers[selectedProvider];

						if (isAdd) {
							const result = await addProvider(selectedProvider);
							if (result.type === 'redirect') {
								window.location.href = result.location;
								return;
							} else if (result.type === 'failure') {
								console.error('Failed to add provider:', result.data);
							}
							return;
						}
						const result = await removeProvider(selectedProvider);
						if (result.type === 'success') {
							console.log('Provider removed successfully');
						}
					}
				}}
			>
				Yes, continue
			</button>
		</form>
	</div>
</dialog>
