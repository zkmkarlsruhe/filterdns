<script lang="ts">
	import { toasts } from '$lib/stores';

	// Toast container
</script>

<div class="app">
	<header>
		<nav>
			<a href="/" class="logo">
				<span class="logo-icon">🛡️</span>
				<span class="logo-text">FilterDNS</span>
			</a>
			<div class="nav-links">
				<a href="/">Home</a>
				<a href="/admin">Admin</a>
			</div>
		</nav>
	</header>

	<main>
		<slot />
	</main>

	<footer>
		<p>FilterDNS - Self-hosted DNS filtering</p>
	</footer>

	<!-- Toast notifications -->
	<div class="toasts">
		{#each $toasts as toast (toast.id)}
			<div class="toast toast-{toast.type}">
				{toast.message}
			</div>
		{/each}
	</div>
</div>

<style>
	.app {
		min-height: 100vh;
		display: flex;
		flex-direction: column;
	}

	header {
		background: var(--bg-secondary);
		border-bottom: 1px solid var(--border);
		padding: 1rem 2rem;
	}

	nav {
		max-width: 1200px;
		margin: 0 auto;
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.logo {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		text-decoration: none;
		color: var(--text);
		font-size: 1.25rem;
		font-weight: 600;
	}

	.logo-icon {
		font-size: 1.5rem;
	}

	.nav-links {
		display: flex;
		gap: 1.5rem;
	}

	.nav-links a {
		color: var(--text-secondary);
		text-decoration: none;
		transition: color 0.2s;
	}

	.nav-links a:hover {
		color: var(--text);
	}

	main {
		flex: 1;
		max-width: 1200px;
		margin: 0 auto;
		padding: 2rem;
		width: 100%;
	}

	footer {
		background: var(--bg-secondary);
		border-top: 1px solid var(--border);
		padding: 1rem 2rem;
		text-align: center;
		color: var(--text-secondary);
		font-size: 0.875rem;
	}

	.toasts {
		position: fixed;
		bottom: 1rem;
		right: 1rem;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		z-index: 1000;
	}

	.toast {
		padding: 0.75rem 1rem;
		border-radius: 0.5rem;
		background: var(--bg-card);
		border: 1px solid var(--border);
		animation: slide-in 0.3s ease;
	}

	.toast-success {
		border-color: var(--success);
	}

	.toast-error {
		border-color: var(--danger);
	}

	@keyframes slide-in {
		from {
			transform: translateX(100%);
			opacity: 0;
		}
		to {
			transform: translateX(0);
			opacity: 1;
		}
	}
</style>
