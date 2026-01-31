<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { createProfile, getProfile, getBlocklists, type Blocklist } from '$lib/api';
	import { toasts } from '$lib/stores';

	// Get token from URL params
	$: token = $page.url.searchParams.get('token');

	let step: 'select' | 'create' | 'password' | 'complete' = 'select';
	let profileName = '';
	let password = '';
	let loading = false;
	let blocklists: Blocklist[] = [];
	let existingProfile = false;

	// Selected profile info for completion
	let selectedProfile: { name: string; password?: string } | null = null;

	onMount(async () => {
		if (!token) {
			toasts.error('No onboarding token provided');
			goto('/');
			return;
		}

		// Load blocklists for preview
		const result = await getBlocklists();
		if (result.data) {
			blocklists = result.data.blocklists;
		}
	});

	async function checkProfile() {
		if (!profileName.trim()) {
			toasts.error('Please enter a profile name');
			return;
		}

		const name = profileName.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
		profileName = name;
		loading = true;

		const result = await getProfile(name);
		loading = false;

		if (result.status === 401) {
			// Profile exists and has password
			existingProfile = true;
			step = 'password';
		} else if (result.data) {
			// Profile exists, no password - use it directly
			selectedProfile = { name };
			step = 'complete';
			await completeOnboarding();
		} else {
			// Profile doesn't exist - create it
			step = 'create';
		}
	}

	async function handlePasswordSubmit() {
		if (!password) {
			toasts.error('Please enter the password');
			return;
		}

		selectedProfile = { name: profileName, password };
		await completeOnboarding();
	}

	async function handleCreateProfile() {
		loading = true;

		const result = await createProfile(profileName, password || undefined);
		loading = false;

		if (result.error) {
			toasts.error(result.error);
			return;
		}

		selectedProfile = { name: profileName, password: password || undefined };
		await completeOnboarding();
	}

	async function completeOnboarding() {
		if (!selectedProfile || !token) return;

		loading = true;
		step = 'complete';

		try {
			// Call the backend to complete onboarding
			const response = await fetch('/api/client/onboard/complete', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					token,
					profile_name: selectedProfile.name,
					password: selectedProfile.password
				})
			});

			const data = await response.json();

			if (!response.ok) {
				toasts.error(data.error || 'Failed to complete onboarding');
				step = 'select';
				loading = false;
				return;
			}

			loading = false;
			toasts.success('Setup complete! You can close this window.');

			// Keep showing success state - the desktop app will pick up the completion
		} catch (err) {
			toasts.error('Network error');
			step = 'select';
			loading = false;
		}
	}

	function goBack() {
		step = 'select';
		password = '';
	}
</script>

<svelte:head>
	<title>Connect to FilterDNS</title>
</svelte:head>

<div class="onboard">
	<div class="header">
		<h1>Connect to FilterDNS</h1>
		<p class="subtitle">Complete this setup to configure your desktop client</p>
	</div>

	{#if !token}
		<div class="card error-card">
			<h2>Invalid Link</h2>
			<p>This onboarding link is invalid or has expired.</p>
			<p>Please start the setup again from your FilterDNS desktop app.</p>
		</div>
	{:else if step === 'select'}
		<div class="card">
			<h2>Select or Create Profile</h2>
			<p class="description">
				Enter your profile name to connect, or create a new one.
			</p>

			<form on:submit|preventDefault={checkProfile}>
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
							disabled={loading}
						/>
						<span class="suffix">.your-domain.com</span>
					</div>
					<small>Use lowercase letters, numbers, and hyphens</small>
				</div>

				<button type="submit" class="btn btn-primary" disabled={loading}>
					{loading ? 'Checking...' : 'Continue'}
				</button>
			</form>
		</div>

	{:else if step === 'password'}
		<div class="card">
			<button class="back-btn" on:click={goBack}>&larr; Back</button>
			<h2>Enter Password</h2>
			<p class="description">
				Profile <strong>{profileName}</strong> is password-protected.
			</p>

			<form on:submit|preventDefault={handlePasswordSubmit}>
				<div class="form-group">
					<label for="password">Password</label>
					<input
						type="password"
						id="password"
						bind:value={password}
						placeholder="Enter profile password"
						required
						disabled={loading}
					/>
				</div>

				<button type="submit" class="btn btn-primary" disabled={loading}>
					{loading ? 'Connecting...' : 'Connect'}
				</button>
			</form>
		</div>

	{:else if step === 'create'}
		<div class="card">
			<button class="back-btn" on:click={goBack}>&larr; Back</button>
			<h2>Create New Profile</h2>
			<p class="description">
				Profile <strong>{profileName}</strong> doesn't exist. Create it now?
			</p>

			<form on:submit|preventDefault={handleCreateProfile}>
				<div class="form-group">
					<label for="create-password">Password (optional)</label>
					<input
						type="password"
						id="create-password"
						bind:value={password}
						placeholder="Protect your profile settings"
						disabled={loading}
					/>
					<small>Leave blank for no password protection</small>
				</div>

				<button type="submit" class="btn btn-primary" disabled={loading}>
					{loading ? 'Creating...' : 'Create & Connect'}
				</button>
			</form>
		</div>

	{:else if step === 'complete'}
		<div class="card success-card">
			{#if loading}
				<div class="spinner"></div>
				<h2>Completing Setup...</h2>
				<p>Please wait while we configure your connection.</p>
			{:else}
				<div class="success-icon">&#10003;</div>
				<h2>Setup Complete!</h2>
				<p>Your FilterDNS client is now connected to profile <strong>{selectedProfile?.name}</strong>.</p>
				<p class="hint">You can close this browser window now.</p>
				<p class="hint">The desktop app will activate DNS filtering automatically.</p>
			{/if}
		</div>
	{/if}

	{#if blocklists.length > 0 && step === 'select'}
		<div class="info-section">
			<h3>What You'll Get</h3>
			<div class="features">
				<div class="feature">
					<span class="icon">&#128683;</span>
					<div>
						<strong>Ad & Tracker Blocking</strong>
						<p>Block ads, trackers, and malware at the DNS level</p>
					</div>
				</div>
				<div class="feature">
					<span class="icon">&#128274;</span>
					<div>
						<strong>Encrypted DNS</strong>
						<p>Your queries are encrypted with DNS-over-HTTPS</p>
					</div>
				</div>
				<div class="feature">
					<span class="icon">&#9881;</span>
					<div>
						<strong>Easy Management</strong>
						<p>Configure blocklists and rules from the web dashboard</p>
					</div>
				</div>
			</div>
		</div>
	{/if}
</div>

<style>
	.onboard {
		max-width: 500px;
		margin: 0 auto;
		padding: 2rem 1rem;
	}

	.header {
		text-align: center;
		margin-bottom: 2rem;
	}

	h1 {
		font-size: 2rem;
		margin-bottom: 0.5rem;
		background: linear-gradient(135deg, var(--primary), #8b5cf6);
		-webkit-background-clip: text;
		-webkit-text-fill-color: transparent;
		background-clip: text;
	}

	.subtitle {
		color: var(--text-secondary);
	}

	.card {
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: 1rem;
		padding: 2rem;
		margin-bottom: 1.5rem;
		position: relative;
	}

	.card h2 {
		margin-bottom: 0.5rem;
	}

	.description {
		color: var(--text-secondary);
		margin-bottom: 1.5rem;
	}

	.back-btn {
		position: absolute;
		top: 1rem;
		left: 1rem;
		background: none;
		border: none;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 0.875rem;
	}

	.back-btn:hover {
		color: var(--text);
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

	input:disabled {
		opacity: 0.6;
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

	.success-card {
		text-align: center;
		padding: 3rem 2rem;
	}

	.success-icon {
		font-size: 4rem;
		color: #22c55e;
		margin-bottom: 1rem;
	}

	.spinner {
		width: 48px;
		height: 48px;
		border: 4px solid var(--border);
		border-top-color: var(--primary);
		border-radius: 50%;
		margin: 0 auto 1rem;
		animation: spin 1s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.hint {
		color: var(--text-secondary);
		font-size: 0.875rem;
		margin-top: 0.5rem;
	}

	.error-card {
		border-color: #ef4444;
	}

	.info-section {
		margin-top: 2rem;
	}

	.info-section h3 {
		margin-bottom: 1rem;
		text-align: center;
	}

	.features {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.feature {
		display: flex;
		align-items: flex-start;
		gap: 1rem;
		padding: 1rem;
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: 0.5rem;
	}

	.feature .icon {
		font-size: 1.5rem;
	}

	.feature strong {
		display: block;
		margin-bottom: 0.25rem;
	}

	.feature p {
		color: var(--text-secondary);
		font-size: 0.875rem;
		margin: 0;
	}
</style>
