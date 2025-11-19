<script>
	import LoginWithGithub from '$lib/components/login-with-github.svelte';
	import LoginWithGoogle from '$lib/components/login-with-google.svelte';
</script>

<div class="flex flex-col items-center justify-center gap-4">
	<h1 class="text-3xl font-bold">Login</h1>
	<p class="text-center text-gray-600">Please choose a login method:</p>
	<LoginWithGoogle />
	<LoginWithGithub />
</div>
