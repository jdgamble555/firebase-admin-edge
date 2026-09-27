<script lang="ts">
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head>
	<title>About</title>
</svelte:head>

<h1 class="text-2xl font-bold">About</h1>
<p class="max-w-prose text-center whitespace-pre-wrap text-gray-700">{data.name}</p>
<p class="max-w-prose text-center whitespace-pre-wrap text-gray-700">{data.description}</p>
