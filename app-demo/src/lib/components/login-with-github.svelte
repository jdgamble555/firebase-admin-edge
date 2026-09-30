<script lang="ts">
	import { page } from '$app/state';
</script>

<form
	method="POST"
	action={`/login?/github&next=${encodeURIComponent(page.url.searchParams.get('next') || '/')}`}
	class="w-full"
>
	<button
		type="submit"
		class="w-full cursor-pointer rounded bg-gray-800 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-gray-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-gray-800"
	>
		Sign in with GitHub
	</button>
</form>
