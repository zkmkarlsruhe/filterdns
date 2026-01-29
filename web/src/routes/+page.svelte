<script lang="ts">
	import { createProfile, getProfile, getBlocklists, type Blocklist } from '$lib/api';
	import { toasts } from '$lib/stores';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let profileName = '';
	let password = '';
	let loading = false;
	let blocklists: Blocklist[] = [];

	onMount(async () => {
		const result = await getBlocklists();
		if (result.data) {
			blocklists = result.data.blocklists;
		}
	});

	async function handleSubmit() {
		if (!profileName.trim()) {
			toasts.error('Please enter a profile name');
			return;
		}

		const name = profileName.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
		if (name !== profileName.trim()) {
			profileName = name;
		}

		loading = true;

		// First check if profile exists
		const existingResult = await getProfile(name);

		if (existingResult.data || existingResult.status === 401) {
			// Profile exists - go to it (401 means it exists but needs password)
			loading = false;
			goto(`/profile/${name}`);
			return;
		}

		// Profile doesn't exist (404) - create it
		const createResult = await createProfile(name, password || undefined);
		loading = false;

		if (createResult.error) {
			toasts.error(createResult.error);
		} else if (createResult.data) {
			toasts.success(`Profile "${name}" created!`);
			goto(`/profile/${name}`);
		}
	}
</script>

<svelte:head>
	<title>FilterDNS</title>
</svelte:head>

<div class="landing">
	<div class="hero">
		<h1>FilterDNS</h1>
		<p class="tagline">Self-hosted DNS filtering for ZKM</p>
	</div>

	<div class="access-section">
		<div class="card">
			<h2>Access Your Profile</h2>
			<p class="description">
				Enter your profile name to access settings, or create a new profile.
			</p>

			<form on:submit|preventDefault={handleSubmit}>
				<div class="form-group">
					<label for="name">Profile Name</label>
					<div class="input-with-suffix">
						<input
							type="text"
							id="name"
							bind:value={profileName}
							placeholder="my-profile"
							pattern="[a-z0-9-]+"
							maxlength="63"
							required
						/>
						<span class="suffix">.filterdns.zkm.de</span>
					</div>
					<small>Use lowercase letters, numbers, and hyphens</small>
				</div>

				<div class="form-group">
					<label for="password">Password (for new profiles)</label>
					<input
						type="password"
						id="password"
						bind:value={password}
						placeholder="Optional - protect your settings"
					/>
					<small>Leave blank if accessing an existing profile</small>
				</div>

				<button type="submit" class="btn btn-primary" disabled={loading}>
					{loading ? 'Loading...' : 'Continue'}
				</button>
			</form>
		</div>
	</div>

	<div class="features">
		<div class="feature">
			<div class="feature-icon">🚫</div>
			<h3>Block Ads & Trackers</h3>
			<p>Choose from popular blocklists to filter unwanted content</p>
		</div>
		<div class="feature">
			<div class="feature-icon">🔒</div>
			<h3>Secure DNS</h3>
			<p>Support for DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT)</p>
		</div>
		<div class="feature">
			<div class="feature-icon">📊</div>
			<h3>Query Logs</h3>
			<p>View and analyze your DNS queries in real-time</p>
		</div>
	</div>

	{#if blocklists.length > 0}
		<div class="blocklists-preview">
			<h2>Available Blocklists</h2>
			<div class="blocklist-grid">
				{#each blocklists.slice(0, 6) as bl}
					<div class="blocklist-card">
						<span class="category">{bl.category || 'general'}</span>
						<h4>{bl.name}</h4>
						<p>{bl.description || 'No description'}</p>
						<span class="count">{bl.domain_count.toLocaleString()} domains</span>
					</div>
				{/each}
			</div>
		</div>
	{/if}
</div>

<style>
	.landing {
		max-width: 800px;
		margin: 0 auto;
	}

	.hero {
		text-align: center;
		margin-bottom: 3rem;
	}

	h1 {
		font-size: 3rem;
		margin-bottom: 0.5rem;
		background: linear-gradient(135deg, var(--primary), #8b5cf6);
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
		background-clip: text;
	}

	.tagline {
		font-size: 1.25rem;
		color: var(--text-secondary);
	}

	.card {
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: 1rem;
		padding: 2rem;
	}

	.card h2 {
		margin-bottom: 0.5rem;
	}

	.description {
		color: var(--text-secondary);
		margin-bottom: 1.5rem;
	}

	.form-group {
		margin-bottom: 1.5rem;
	}

	label {
		display: block;
		margin-bottom: 0.5rem;
		font-weight: 500;
	}

	input {
		width: 100%;
		padding: 0.75rem 1rem;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 0.5rem;
		color: var(--text);
		font-size: 1rem;
	}

	input:focus {
		outline: none;
		border-color: var(--primary);
	}

	.input-with-suffix {
		display: flex;
		align-items: center;
	}

	.input-with-suffix input {
		border-top-right-radius: 0;
		border-bottom-right-radius: 0;
	}

	.suffix {
		background: var(--bg);
		border: 1px solid var(--border);
		border-left: none;
		padding: 0.75rem 1rem;
		border-radius: 0 0.5rem 0.5rem 0;
		color: var(--text-secondary);
		white-space: nowrap;
	}

	small {
		display: block;
		margin-top: 0.25rem;
		color: var(--text-secondary);
		font-size: 0.875rem;
	}

	.btn {
		padding: 0.75rem 1.5rem;
		border-radius: 0.5rem;
		font-size: 1rem;
		font-weight: 500;
		cursor: pointer;
		border: none;
		transition: all 0.2s;
	}

	.btn-primary {
		background: var(--primary);
		color: white;
		width: 100%;
	}

	.btn-primary:hover:not(:disabled) {
		background: var(--primary-dark);
	}

	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.features {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 1.5rem;
		margin-top: 3rem;
	}

	.feature {
		text-align: center;
		padding: 1.5rem;
	}

	.feature-icon {
		font-size: 2.5rem;
		margin-bottom: 1rem;
	}

	.feature h3 {
		margin-bottom: 0.5rem;
	}

	.feature p {
		color: var(--text-secondary);
		font-size: 0.875rem;
	}

	.blocklists-preview {
		margin-top: 3rem;
	}

	.blocklists-preview h2 {
		margin-bottom: 1.5rem;
		text-align: center;
	}

	.blocklist-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 1rem;
	}

	.blocklist-card {
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: 0.5rem;
		padding: 1rem;
	}

	.blocklist-card .category {
		font-size: 0.75rem;
		text-transform: uppercase;
		color: var(--primary);
	}

	.blocklist-card h4 {
		margin: 0.25rem 0;
	}

	.blocklist-card p {
		font-size: 0.875rem;
		color: var(--text-secondary);
		margin: 0.5rem 0;
	}

	.blocklist-card .count {
		font-size: 0.75rem;
		color: var(--text-secondary);
	}

	@media (max-width: 768px) {
		.features {
			grid-template-columns: 1fr;
		}

		.blocklist-grid {
			grid-template-columns: 1fr;
		}

		h1 {
			font-size: 2rem;
		}
	}
</style>
