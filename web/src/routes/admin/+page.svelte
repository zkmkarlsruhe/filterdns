<script lang="ts">
	import { onMount } from 'svelte';
	import {
		adminLogin,
		adminLogout,
		adminGetProfiles,
		adminGetStats,
		adminGetSettings,
		adminUpdateSettings,
		getBlocklists,
		type AdminProfile,
		type GlobalStats,
		type Blocklist
	} from '$lib/api';
	import { isAdmin, toasts } from '$lib/stores';

	let password = '';
	let loggingIn = false;
	let profiles: AdminProfile[] = [];
	let stats: GlobalStats | null = null;
	let loading = true;

	// Settings state
	let allBlocklists: Blocklist[] = [];
	let defaultBlocklists: string[] = [];
	let savingSettings = false;
	let expandedSettingsCategories: Set<string> = new Set();

	// Group blocklists by category
	$: blocklistsByCategory = allBlocklists
		.filter(bl => bl.domain_count > 0)
		.reduce((acc, bl) => {
			const category = bl.category || 'other';
			if (!acc[category]) acc[category] = [];
			acc[category].push(bl);
			return acc;
		}, {} as Record<string, Blocklist[]>);

	$: sortedCategories = Object.keys(blocklistsByCategory).sort();

	onMount(async () => {
		if ($isAdmin) {
			await loadData();
		}
		loading = false;
	});

	async function handleLogin() {
		loggingIn = true;
		const result = await adminLogin(password);
		loggingIn = false;

		if (result.error) {
			toasts.error(result.error);
		} else {
			isAdmin.set(true);
			password = '';
			await loadData();
		}
	}

	async function handleLogout() {
		await adminLogout();
		isAdmin.set(false);
		profiles = [];
		stats = null;
		allBlocklists = [];
		defaultBlocklists = [];
	}

	async function loadData() {
		loading = true;
		const [profilesResult, statsResult, settingsResult, blocklistsResult] = await Promise.all([
			adminGetProfiles(),
			adminGetStats(),
			adminGetSettings(),
			getBlocklists()
		]);

		if (profilesResult.data) {
			profiles = profilesResult.data.profiles;
		}
		if (statsResult.data) {
			stats = statsResult.data;
		}
		if (settingsResult.data) {
			defaultBlocklists = settingsResult.data.default_blocklists || [];
		}
		if (blocklistsResult.data) {
			allBlocklists = blocklistsResult.data.blocklists;
		}
		loading = false;
	}

	function toggleSettingsCategory(category: string) {
		if (expandedSettingsCategories.has(category)) {
			expandedSettingsCategories.delete(category);
		} else {
			expandedSettingsCategories.add(category);
		}
		expandedSettingsCategories = expandedSettingsCategories;
	}

	function toggleDefaultBlocklist(blocklistId: string) {
		if (defaultBlocklists.includes(blocklistId)) {
			defaultBlocklists = defaultBlocklists.filter(id => id !== blocklistId);
		} else {
			defaultBlocklists = [...defaultBlocklists, blocklistId];
		}
	}

	function toggleCategoryDefaults(category: string) {
		const categoryBlocklists = blocklistsByCategory[category] || [];
		const allEnabled = categoryBlocklists.every(bl => defaultBlocklists.includes(bl.id));

		if (allEnabled) {
			// Disable all in category
			defaultBlocklists = defaultBlocklists.filter(
				id => !categoryBlocklists.some(bl => bl.id === id)
			);
		} else {
			// Enable all in category
			const newIds = categoryBlocklists.map(bl => bl.id).filter(id => !defaultBlocklists.includes(id));
			defaultBlocklists = [...defaultBlocklists, ...newIds];
		}
	}

	function getCategoryStats(category: string) {
		const lists = blocklistsByCategory[category] || [];
		const enabled = lists.filter(bl => defaultBlocklists.includes(bl.id)).length;
		return { total: lists.length, enabled };
	}

	async function saveSettings() {
		savingSettings = true;
		const result = await adminUpdateSettings({ default_blocklists: defaultBlocklists });
		savingSettings = false;

		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Settings saved');
		}
	}
</script>

<svelte:head>
	<title>Admin - FilterDNS</title>
</svelte:head>

<div class="admin-page">
	{#if !$isAdmin}
		<div class="login-card">
			<h1>Admin Login</h1>
			<form on:submit|preventDefault={handleLogin}>
				<div class="form-group">
					<input
						type="password"
						bind:value={password}
						placeholder="Admin password"
						required
					/>
				</div>
				<button type="submit" class="btn btn-primary" disabled={loggingIn}>
					{loggingIn ? 'Logging in...' : 'Login'}
				</button>
			</form>
		</div>
	{:else}
		<header class="page-header">
			<h1>Admin Dashboard</h1>
			<button class="btn btn-outline" on:click={handleLogout}>Logout</button>
		</header>

		{#if loading}
			<div class="loading">Loading...</div>
		{:else}
			{#if stats}
				<section class="stats-grid">
					<div class="stat-card">
						<div class="stat-value">{stats.total_profiles}</div>
						<div class="stat-label">Total Profiles</div>
					</div>
					<div class="stat-card">
						<div class="stat-value">{stats.total_queries_today.toLocaleString()}</div>
						<div class="stat-label">Queries Today</div>
					</div>
					<div class="stat-card">
						<div class="stat-value">{stats.total_blocked_today.toLocaleString()}</div>
						<div class="stat-label">Blocked Today</div>
					</div>
					<div class="stat-card">
						<div class="stat-value">{stats.blocked_percentage}%</div>
						<div class="stat-label">Block Rate</div>
					</div>
					<div class="stat-card">
						<div class="stat-value">{stats.active_blocklists}</div>
						<div class="stat-label">Active Blocklists</div>
					</div>
					<div class="stat-card">
						<div class="stat-value">{stats.total_blocked_domains.toLocaleString()}</div>
						<div class="stat-label">Blocked Domains</div>
					</div>
				</section>
			{/if}

			<!-- Default Settings Section -->
			<section class="card settings-section">
				<div class="settings-header">
					<div>
						<h2>Default Settings for New Profiles</h2>
						<p class="settings-description">
							Select which blocklists should be enabled by default when a new profile is created.
						</p>
					</div>
					<button
						class="btn btn-primary"
						on:click={saveSettings}
						disabled={savingSettings}
					>
						{savingSettings ? 'Saving...' : 'Save Settings'}
					</button>
				</div>

				<div class="default-blocklists">
					<h3>Default Blocklists ({defaultBlocklists.length} selected)</h3>
					<div class="category-list">
						{#each sortedCategories as category}
							{@const stats = getCategoryStats(category)}
							<div class="category-group">
								<div class="category-header">
									<label class="category-checkbox">
										<input
											type="checkbox"
											checked={stats.enabled === stats.total && stats.total > 0}
											indeterminate={stats.enabled > 0 && stats.enabled < stats.total}
											on:change={() => toggleCategoryDefaults(category)}
										/>
										<span class="category-name">{category}</span>
									</label>
									<button
										class="category-expand"
										on:click={() => toggleSettingsCategory(category)}
									>
										<span class="category-count">{stats.enabled}/{stats.total}</span>
										<span class="expand-icon">{expandedSettingsCategories.has(category) ? '▼' : '▶'}</span>
									</button>
								</div>

								{#if expandedSettingsCategories.has(category)}
									<div class="category-blocklists">
										{#each blocklistsByCategory[category] as bl}
											<label class="blocklist-item">
												<input
													type="checkbox"
													checked={defaultBlocklists.includes(bl.id)}
													on:change={() => toggleDefaultBlocklist(bl.id)}
												/>
												<div class="blocklist-info">
													<span class="blocklist-name">{bl.name}</span>
													<span class="blocklist-domains">{bl.domain_count.toLocaleString()} domains</span>
												</div>
											</label>
										{/each}
									</div>
								{/if}
							</div>
						{/each}
					</div>
				</div>
			</section>

			<section class="card">
				<h2>All Profiles</h2>
				{#if profiles.length > 0}
					<div class="table-wrapper">
						<table>
							<thead>
								<tr>
									<th>Name</th>
									<th>Queries (24h)</th>
									<th>Block Rate</th>
									<th>Status</th>
									<th>Created</th>
								</tr>
							</thead>
							<tbody>
								{#each profiles as profile}
									<tr>
										<td>
											<a href="/profile/{profile.name}">{profile.name}</a>
											{#if profile.has_password}
												<span class="badge">Password</span>
											{/if}
										</td>
										<td>{profile.total_queries_24h.toLocaleString()}</td>
										<td>{profile.blocked_percentage}%</td>
										<td>
											{#if profile.is_filtering_paused}
												<span class="status-paused">Paused</span>
											{:else}
												<span class="status-active">Active</span>
											{/if}
										</td>
										<td>{new Date(profile.created_at).toLocaleDateString()}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{:else}
					<p class="empty">No profiles yet</p>
				{/if}
			</section>

			{#if stats?.loaded_blocklists}
				<section class="card">
					<h2>Loaded Blocklists</h2>
					<div class="blocklist-tags">
						{#each stats.loaded_blocklists as bl}
							<span class="tag">{bl}</span>
						{/each}
					</div>
				</section>
			{/if}
		{/if}
	{/if}
</div>

<style>
	.admin-page {
		max-width: 1000px;
		margin: 0 auto;
	}

	.login-card {
		max-width: 400px;
		margin: 3rem auto;
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: 1rem;
		padding: 2rem;
		text-align: center;
	}

	.login-card h1 {
		margin-bottom: 1.5rem;
	}

	.form-group {
		margin-bottom: 1rem;
	}

	input[type="password"] {
		width: 100%;
		padding: 0.75rem 1rem;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 0.5rem;
		color: var(--text);
		font-size: 1rem;
	}

	.page-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 2rem;
	}

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 1rem;
		margin-bottom: 2rem;
	}

	.stat-card {
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: 0.5rem;
		padding: 1.5rem;
		text-align: center;
	}

	.stat-value {
		font-size: 2rem;
		font-weight: 600;
	}

	.stat-label {
		color: var(--text-secondary);
	}

	.card {
		background: var(--bg-card);
		border: 1px solid var(--border);
		border-radius: 0.5rem;
		padding: 1.5rem;
		margin-bottom: 1.5rem;
	}

	.card h2 {
		margin: 0 0 1rem 0;
	}

	/* Settings Section */
	.settings-section {
		border-color: var(--primary);
	}

	.settings-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: 1.5rem;
		gap: 1rem;
	}

	.settings-description {
		color: var(--text-secondary);
		margin: 0.5rem 0 0 0;
		font-size: 0.875rem;
	}

	.default-blocklists h3 {
		margin: 0 0 1rem 0;
		font-size: 1rem;
		color: var(--text-secondary);
	}

	.category-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.category-group {
		border: 1px solid var(--border);
		border-radius: 0.5rem;
		overflow: hidden;
	}

	.category-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.75rem 1rem;
		background: var(--bg);
	}

	.category-checkbox {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		cursor: pointer;
	}

	.category-checkbox input[type="checkbox"] {
		width: 1.25rem;
		height: 1.25rem;
		cursor: pointer;
	}

	.category-name {
		font-weight: 500;
		text-transform: capitalize;
	}

	.category-expand {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		background: none;
		border: none;
		color: var(--text-secondary);
		cursor: pointer;
		padding: 0.25rem;
	}

	.category-count {
		font-size: 0.875rem;
	}

	.expand-icon {
		font-size: 0.75rem;
	}

	.category-blocklists {
		padding: 0.5rem 1rem;
		border-top: 1px solid var(--border);
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.blocklist-item {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.5rem;
		border-radius: 0.25rem;
		cursor: pointer;
	}

	.blocklist-item:hover {
		background: var(--bg);
	}

	.blocklist-item input[type="checkbox"] {
		width: 1rem;
		height: 1rem;
		cursor: pointer;
	}

	.blocklist-info {
		display: flex;
		flex-direction: column;
	}

	.blocklist-name {
		font-size: 0.875rem;
	}

	.blocklist-domains {
		font-size: 0.75rem;
		color: var(--text-secondary);
	}

	.table-wrapper {
		overflow-x: auto;
	}

	table {
		width: 100%;
		border-collapse: collapse;
	}

	th,
	td {
		padding: 0.75rem;
		text-align: left;
		border-bottom: 1px solid var(--border);
	}

	th {
		color: var(--text-secondary);
		font-weight: 500;
	}

	td a {
		color: var(--primary);
		text-decoration: none;
	}

	td a:hover {
		text-decoration: underline;
	}

	.badge {
		font-size: 0.625rem;
		padding: 0.125rem 0.375rem;
		background: var(--primary);
		color: white;
		border-radius: 0.25rem;
		margin-left: 0.5rem;
		vertical-align: middle;
	}

	.status-active {
		color: var(--success);
	}

	.status-paused {
		color: var(--warning);
	}

	.blocklist-tags {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
	}

	.tag {
		background: var(--bg);
		padding: 0.25rem 0.75rem;
		border-radius: 1rem;
		font-size: 0.875rem;
	}

	.empty {
		color: var(--text-secondary);
		text-align: center;
		padding: 2rem;
	}

	.loading {
		text-align: center;
		padding: 3rem;
		color: var(--text-secondary);
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
	}

	.btn-primary:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.btn-outline {
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text);
	}

	@media (max-width: 768px) {
		.stats-grid {
			grid-template-columns: repeat(2, 1fr);
		}

		.settings-header {
			flex-direction: column;
		}

		.settings-header .btn {
			width: 100%;
		}
	}
</style>
