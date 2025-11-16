<script lang="ts">
	import type { PageProps } from './$types';

	const { data }: PageProps = $props();
</script>

<section class="flex flex-col items-center">
	<h1 class="mb-2 text-3xl font-bold text-gray-900">{data.about.description}</h1>
	<p class="text-lg text-gray-600">{data.about.name}</p>
</section>