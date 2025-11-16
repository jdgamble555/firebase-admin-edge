<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import Logout from '$lib/components/logout.svelte';
	import { page } from '$app/state';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<main class="mt-5 flex flex-col items-center justify-center gap-5">
	{@render children()}
	<nav class="flex items-center justify-center gap-3">
		<a href="/" class="font-medium text-gray-700 hover:text-blue-600">Home</a>
		<a href="/about" class="font-medium text-gray-700 hover:text-blue-600">About</a>
		{#if page.data.user}
			<Logout />
		{:else}
			<a href="/login" class="font-medium text-gray-700 hover:text-blue-600">Login</a>
		{/if}
	</nav>
</main>
