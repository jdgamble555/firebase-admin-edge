<script lang="ts">
	import { page } from '$app/state';
</script>

<form
	method="POST"
	action={`/login?/google&next=${encodeURIComponent(page.url.searchParams.get('next') || '/')}`}
	class="w-full"
>
	<button
		type="submit"
		class="w-full cursor-pointer rounded bg-red-600 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-red-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"
	>
		Sign in with Google
	</button>
</form>
