<script lang="ts">
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import {
		getProfile,
		getBlocklists,
		updateProfile,
		pauseFiltering,
		resumeFiltering,
		getProfileLogs,
		createRule,
		deleteRule,
		type ProfileDetails,
		type Blocklist,
		type QueryLog
	} from '$lib/api';
	import { toasts } from '$lib/stores';

	let profile: ProfileDetails | null = null;
	let blocklists: Blocklist[] = [];
	let logs: QueryLog[] = [];
	let loading = true;
	let error = '';

	// Auth state
	let needsPassword = false;
	let passwordInput = '';
	let authPassword: string | undefined = undefined;

	// Form state
	let newRuleDomain = '';
	let newRuleType: 'allow' | 'deny' = 'allow';
	let showBlockedOnly = false;
	let expandedCategories: Set<string> = new Set();

	// Password management
	let showPasswordSection = false;
	let newPassword = '';
	let confirmPassword = '';
	let savingPassword = false;

	$: profileName = $page.params.name;

	// Normalize category names (consolidate social-* into social, etc.)
	function normalizeCategory(category: string | null): string {
		if (!category) return 'other';
		// Consolidate social media sub-categories
		if (category.startsWith('social-')) return 'social';
		// Consolidate bigtech into one
		if (category === 'bigtech') return 'big-tech';
		return category;
	}

	// Group blocklists by category, filtering out empty ones
	$: blocklistsByCategory = blocklists
		.filter(bl => bl.domain_count > 0) // Only show lists with domains
		.reduce((acc, bl) => {
			const category = normalizeCategory(bl.category);
			if (!acc[category]) {
				acc[category] = [];
			}
			acc[category].push(bl);
			return acc;
		}, {} as Record<string, Blocklist[]>);

	// Sort categories alphabetically, but put common ones first
	const categoryOrder = ['ads', 'malware', 'tracking', 'adult', 'social', 'gaming', 'streaming', 'family', 'big-tech'];
	$: sortedCategories = Object.keys(blocklistsByCategory).sort((a, b) => {
		const aIndex = categoryOrder.indexOf(a);
		const bIndex = categoryOrder.indexOf(b);
		if (aIndex !== -1 && bIndex !== -1) return aIndex - bIndex;
		if (aIndex !== -1) return -1;
		if (bIndex !== -1) return 1;
		return a.localeCompare(b);
	});

	function toggleCategoryExpand(category: string) {
		if (expandedCategories.has(category)) {
			expandedCategories.delete(category);
		} else {
			expandedCategories.add(category);
		}
		expandedCategories = expandedCategories; // trigger reactivity
	}

	function getCategoryStats(category: string) {
		const lists = blocklistsByCategory[category] || [];
		const enabled = lists.filter(bl => profile?.blocklists.includes(bl.id)).length;
		const allEnabled = lists.length > 0 && enabled === lists.length;
		return { total: lists.length, enabled, allEnabled };
	}

	onMount(async () => {
		await loadData();
	});

	async function loadData() {
		loading = true;
		error = '';
		needsPassword = false;

		const profileResult = await getProfile(profileName, authPassword);

		if (profileResult.status === 401) {
			loading = false;
			needsPassword = true;
			error = '';
			return;
		}

		if (profileResult.error) {
			loading = false;
			error = profileResult.error;
			return;
		}

		// Profile loaded successfully, now load other data
		const [blocklistsResult, logsResult] = await Promise.all([
			getBlocklists(),
			getProfileLogs(profileName, { limit: 50 }, authPassword)
		]);

		loading = false;
		profile = profileResult.data || null;
		blocklists = blocklistsResult.data?.blocklists || [];
		logs = logsResult.data?.logs || [];
	}

	async function handlePasswordSubmit() {
		authPassword = passwordInput;
		await loadData();
		if (needsPassword) {
			toasts.error('Incorrect password');
			passwordInput = '';
			authPassword = undefined;
		}
	}

	async function toggleBlocklist(blocklistId: string) {
		if (!profile) return;

		const newBlocklists = profile.blocklists.includes(blocklistId)
			? profile.blocklists.filter((id) => id !== blocklistId)
			: [...profile.blocklists, blocklistId];

		const result = await updateProfile(profileName, { blocklists: newBlocklists }, authPassword);
		if (result.error) {
			toasts.error(result.error);
		} else {
			profile.blocklists = newBlocklists;
			toasts.success('Blocklists updated');
		}
	}

	async function toggleCategory(category: string) {
		if (!profile) return;

		const categoryLists = blocklistsByCategory[category] || [];
		const allEnabled = categoryLists.every(bl => profile!.blocklists.includes(bl.id));

		let newBlocklists: string[];
		if (allEnabled) {
			// Disable all in category
			newBlocklists = profile.blocklists.filter(id => !categoryLists.some(bl => bl.id === id));
		} else {
			// Enable all in category
			const toAdd = categoryLists.map(bl => bl.id).filter(id => !profile!.blocklists.includes(id));
			newBlocklists = [...profile.blocklists, ...toAdd];
		}

		const result = await updateProfile(profileName, { blocklists: newBlocklists }, authPassword);
		if (result.error) {
			toasts.error(result.error);
		} else {
			profile.blocklists = newBlocklists;
			toasts.success('Blocklists updated');
		}
	}

	async function handlePause(minutes: number) {
		const result = await pauseFiltering(profileName, minutes, authPassword);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success(`Filtering paused for ${minutes} minutes`);
			await loadData();
		}
	}

	async function handleResume() {
		const result = await resumeFiltering(profileName, authPassword);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Filtering resumed');
			await loadData();
		}
	}

	async function handleAddRule() {
		if (!newRuleDomain.trim()) return;

		const result = await createRule(profileName, newRuleDomain.trim(), newRuleType, authPassword);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Rule added');
			newRuleDomain = '';
			await loadData();
		}
	}

	async function handleDeleteRule(ruleId: string) {
		const result = await deleteRule(profileName, ruleId, authPassword);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Rule deleted');
			await loadData();
		}
	}

	async function refreshLogs() {
		const result = await getProfileLogs(profileName, {
			limit: 50,
			blocked: showBlockedOnly
		}, authPassword);
		if (result.data) {
			logs = result.data.logs;
		}
	}

	function copyToClipboard(text: string) {
		navigator.clipboard.writeText(text);
		toasts.success('Copied to clipboard');
	}

	async function handleSetPassword() {
		if (newPassword !== confirmPassword) {
			toasts.error('Passwords do not match');
			return;
		}

		savingPassword = true;
		const result = await updateProfile(profileName, { password: newPassword || null }, authPassword);
		savingPassword = false;

		if (result.error) {
			toasts.error(result.error);
		} else {
			if (newPassword) {
				toasts.success('Password set successfully');
				authPassword = newPassword; // Update auth for subsequent requests
			} else {
				toasts.success('Password removed');
				authPassword = undefined;
			}
			newPassword = '';
			confirmPassword = '';
			showPasswordSection = false;
			await loadData();
		}
	}

	async function handleRemovePassword() {
		savingPassword = true;
		const result = await updateProfile(profileName, { password: null }, authPassword);
		savingPassword = false;

		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Password removed');
			authPassword = undefined;
			await loadData();
		}
	}
</script>

<svelte:head>
	<title>{profileName} - FilterDNS</title>
</svelte:head>

{#if loading}
	<div class="loading">Loading...</div>
{:else if needsPassword}
	<div class="password-prompt">
		<div class="card">
			<h2>Password Required</h2>
			<p>This profile is password protected. Enter the password to access settings.</p>
			<form on:submit|preventDefault={handlePasswordSubmit}>
				<input
					type="password"
					bind:value={passwordInput}
					placeholder="Enter password"
					autofocus
				/>
				<button type="submit" class="btn btn-primary">Unlock</button>
			</form>
			<a href="/">Go back home</a>
		</div>
	</div>
{:else if error}
	<div class="error">
		<h2>Error</h2>
		<p>{error}</p>
		<a href="/">Go back home</a>
	</div>
{:else if profile}
	<div class="profile-page">
		<header class="page-header">
			<div>
				<h1>{profile.name}</h1>
				<p class="endpoint">{profile.dns_endpoint}</p>
			</div>
			{#if profile.is_filtering_paused}
				<div class="pause-banner">
					<span>Filtering paused until {new Date(profile.filtering_paused_until || '').toLocaleTimeString()}</span>
					<button class="btn btn-small" on:click={handleResume}>Resume</button>
				</div>
			{:else}
				<div class="pause-controls">
					<span>Pause filtering:</span>
					<button class="btn btn-small btn-outline" on:click={() => handlePause(5)}>5 min</button>
					<button class="btn btn-small btn-outline" on:click={() => handlePause(15)}>15 min</button>
					<button class="btn btn-small btn-outline" on:click={() => handlePause(30)}>30 min</button>
				</div>
			{/if}
		</header>

		<!-- Stats -->
		<section class="stats-section">
			<div class="stat-card">
				<div class="stat-value">{profile.stats.total_queries.toLocaleString()}</div>
				<div class="stat-label">Queries (24h)</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">{profile.stats.blocked_queries.toLocaleString()}</div>
				<div class="stat-label">Blocked</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">{profile.stats.blocked_percentage}%</div>
				<div class="stat-label">Block Rate</div>
			</div>
		</section>

		<!-- Setup Instructions -->
		<section class="card">
			<h2>Setup Instructions</h2>
			<div class="setup-grid">
				<div class="setup-item">
					<h4>DNS-over-HTTPS (DoH)</h4>
					<code on:click={() => copyToClipboard(profile?.doh_url || '')}>{profile.doh_url}</code>
				</div>
				<div class="setup-item">
					<h4>DNS-over-TLS (DoT)</h4>
					<code on:click={() => copyToClipboard(profile?.dot_hostname || '')}>{profile.dot_hostname}</code>
				</div>
			</div>
		</section>

		<!-- Password Settings -->
		<section class="card">
			<div class="card-header">
				<h2>Password Protection</h2>
				{#if !showPasswordSection}
					<button class="btn btn-small btn-outline" on:click={() => showPasswordSection = true}>
						{profile.has_password ? 'Change Password' : 'Set Password'}
					</button>
				{/if}
			</div>

			{#if profile.has_password && !showPasswordSection}
				<p class="password-status enabled">
					<span class="status-icon">🔒</span>
					This profile is password protected.
					<button class="btn-link" on:click={handleRemovePassword} disabled={savingPassword}>
						Remove password
					</button>
				</p>
			{:else if !showPasswordSection}
				<p class="password-status disabled">
					<span class="status-icon">🔓</span>
					No password set. Anyone with the profile name can access settings.
				</p>
			{/if}

			{#if showPasswordSection}
				<form class="password-form" on:submit|preventDefault={handleSetPassword}>
					<div class="form-group">
						<label for="new-password">{profile.has_password ? 'New Password' : 'Password'}</label>
						<input
							type="password"
							id="new-password"
							bind:value={newPassword}
							placeholder="Enter password"
						/>
					</div>
					<div class="form-group">
						<label for="confirm-password">Confirm Password</label>
						<input
							type="password"
							id="confirm-password"
							bind:value={confirmPassword}
							placeholder="Confirm password"
						/>
					</div>
					<div class="form-actions">
						<button type="submit" class="btn btn-primary" disabled={savingPassword}>
							{savingPassword ? 'Saving...' : 'Save Password'}
						</button>
						<button type="button" class="btn btn-outline" on:click={() => {
							showPasswordSection = false;
							newPassword = '';
							confirmPassword = '';
						}}>
							Cancel
						</button>
					</div>
					<small class="form-hint">Leave blank to remove password protection.</small>
				</form>
			{/if}
		</section>

		<!-- Blocklists -->
		<section class="card">
			<h2>Blocklists</h2>
			<p class="card-description">Select categories or individual lists to enable filtering.</p>
			<div class="category-list">
				{#each sortedCategories as category}
					{@const stats = getCategoryStats(category)}
					<div class="category-group">
						<div class="category-header">
							<button
								class="category-toggle"
								class:enabled={stats.allEnabled}
								class:partial={stats.enabled > 0 && !stats.allEnabled}
								on:click|stopPropagation={() => toggleCategory(category)}
								title={stats.allEnabled ? 'Disable all in category' : 'Enable all in category'}
							>
								{#if stats.allEnabled}
									✓
								{:else if stats.enabled > 0}
									−
								{/if}
							</button>
							<button
								class="category-expand"
								class:expanded={expandedCategories.has(category)}
								on:click={() => toggleCategoryExpand(category)}
							>
								<span class="category-name">{category}</span>
								<span class="category-stats">
									{#if stats.enabled > 0}
										<span class="enabled-count">{stats.enabled}/{stats.total}</span>
									{:else}
										<span class="total-count">{stats.total} lists</span>
									{/if}
								</span>
								<span class="expand-icon">{expandedCategories.has(category) ? '▼' : '▶'}</span>
							</button>
						</div>
						{#if expandedCategories.has(category)}
							<div class="blocklist-list">
								{#each blocklistsByCategory[category] as bl}
									<label class="blocklist-item">
										<input
											type="checkbox"
											checked={profile.blocklists.includes(bl.id)}
											on:change={() => toggleBlocklist(bl.id)}
										/>
										<div class="blocklist-info">
											<span class="name">{bl.name}</span>
											<span class="meta">{bl.domain_count.toLocaleString()} domains</span>
											{#if bl.description}
												<span class="description">{bl.description}</span>
											{/if}
										</div>
									</label>
								{/each}
							</div>
						{/if}
					</div>
				{/each}
			</div>
		</section>

		<!-- Custom Rules -->
		<section class="card">
			<h2>Custom Rules</h2>
			<form class="add-rule-form" on:submit|preventDefault={handleAddRule}>
				<input type="text" bind:value={newRuleDomain} placeholder="example.com" />
				<select bind:value={newRuleType}>
					<option value="allow">Allow</option>
					<option value="deny">Deny</option>
				</select>
				<button type="submit" class="btn btn-primary">Add</button>
			</form>
			{#if profile.rules.length > 0}
				<div class="rules-list">
					{#each profile.rules as rule}
						<div class="rule-item">
							<span class="rule-type rule-{rule.rule_type}">{rule.rule_type}</span>
							<span class="rule-domain">{rule.domain}</span>
							<button class="btn btn-small btn-danger" on:click={() => handleDeleteRule(rule.id)}>
								Delete
							</button>
						</div>
					{/each}
				</div>
			{:else}
				<p class="empty">No custom rules</p>
			{/if}
		</section>

		<!-- Query Logs -->
		<section class="card">
			<div class="card-header">
				<h2>Recent Queries</h2>
				<div class="log-controls">
					<label>
						<input type="checkbox" bind:checked={showBlockedOnly} on:change={refreshLogs} />
						Blocked only
					</label>
					<button class="btn btn-small btn-outline" on:click={refreshLogs}>Refresh</button>
				</div>
			</div>
			{#if logs.length > 0}
				<div class="logs-table">
					<table>
						<thead>
							<tr>
								<th>Time</th>
								<th>Domain</th>
								<th>Type</th>
								<th>Status</th>
							</tr>
						</thead>
						<tbody>
							{#each logs as log}
								<tr class:blocked={log.blocked}>
									<td>{new Date(log.timestamp).toLocaleTimeString()}</td>
									<td class="domain">{log.domain}</td>
									<td>{log.query_type}</td>
									<td>
										{#if log.blocked}
											<span class="status-blocked">Blocked</span>
										{:else}
											<span class="status-allowed">Allowed</span>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else}
				<p class="empty">No queries yet</p>
			{/if}
		</section>
	</div>
{/if}

<style>
	.loading,
	.error {
		text-align: center;
		padding: 3rem;
	}

	.error h2 {
		color: var(--danger);
	}

	.profile-page {
		display: flex;
		flex-direction: column;
		gap: 1.5rem;
	}

	.page-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		flex-wrap: wrap;
		gap: 1rem;
	}

	.page-header h1 {
		margin: 0;
	}

	.endpoint {
		color: var(--text-secondary);
		margin: 0;
	}

	.pause-banner {
		background: var(--warning);
		color: black;
		padding: 0.5rem 1rem;
		border-radius: 0.5rem;
		display: flex;
		align-items: center;
		gap: 1rem;
	}

	.pause-controls {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.stats-section {
		display: grid;
		grid-template-columns: repeat(3, 1fr);
		gap: 1rem;
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
	}

	.card h2 {
		margin: 0 0 1rem 0;
	}

	.card-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	.card-header h2 {
		margin: 0;
	}

	.setup-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 1rem;
	}

	.setup-item h4 {
		margin: 0 0 0.5rem 0;
		color: var(--text-secondary);
	}

	.setup-item code {
		display: block;
		background: var(--bg);
		padding: 0.75rem;
		border-radius: 0.25rem;
		cursor: pointer;
		word-break: break-all;
	}

	.setup-item code:hover {
		background: var(--bg-secondary);
	}

	.password-prompt {
		display: flex;
		justify-content: center;
		align-items: center;
		min-height: 50vh;
	}

	.password-prompt .card {
		max-width: 400px;
		text-align: center;
	}

	.password-prompt h2 {
		margin-bottom: 0.5rem;
	}

	.password-prompt p {
		color: var(--text-secondary);
		margin-bottom: 1.5rem;
	}

	.password-prompt form {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		margin-bottom: 1rem;
	}

	.password-prompt input {
		padding: 0.75rem 1rem;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 0.5rem;
		color: var(--text);
		font-size: 1rem;
	}

	.password-prompt a {
		color: var(--text-secondary);
	}

	.password-status {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 1rem;
		border-radius: 0.5rem;
	}

	.password-status.enabled {
		background: rgba(16, 185, 129, 0.1);
		color: var(--success);
	}

	.password-status.disabled {
		background: rgba(245, 158, 11, 0.1);
		color: var(--warning);
	}

	.status-icon {
		font-size: 1.25rem;
	}

	.btn-link {
		background: none;
		border: none;
		color: var(--primary);
		cursor: pointer;
		text-decoration: underline;
		padding: 0;
		margin-left: 0.5rem;
	}

	.btn-link:hover {
		color: var(--primary-dark);
	}

	.btn-link:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.password-form {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.password-form .form-group {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.password-form label {
		font-weight: 500;
	}

	.password-form input {
		padding: 0.75rem 1rem;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 0.5rem;
		color: var(--text);
		font-size: 1rem;
	}

	.form-actions {
		display: flex;
		gap: 0.5rem;
	}

	.form-hint {
		color: var(--text-secondary);
		font-size: 0.85rem;
	}

	.card-description {
		color: var(--text-secondary);
		margin-bottom: 1rem;
		font-size: 0.9rem;
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
		align-items: center;
		width: 100%;
		background: var(--bg);
	}

	.category-toggle {
		width: 2.5rem;
		height: 2.5rem;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--bg-secondary);
		border: 1px solid var(--border);
		border-radius: 0.25rem;
		margin: 0.5rem;
		cursor: pointer;
		color: var(--text-secondary);
		font-size: 1rem;
		font-weight: bold;
	}

	.category-toggle:hover {
		background: var(--primary);
		border-color: var(--primary);
		color: white;
	}

	.category-toggle.enabled {
		background: var(--success);
		border-color: var(--success);
		color: white;
	}

	.category-toggle.partial {
		background: var(--warning);
		border-color: var(--warning);
		color: black;
	}

	.category-expand {
		flex: 1;
		display: flex;
		align-items: center;
		padding: 1rem 1rem 1rem 0;
		background: transparent;
		border: none;
		cursor: pointer;
		color: var(--text);
		font-size: 1rem;
		text-align: left;
	}

	.category-expand:hover {
		background: var(--bg-secondary);
	}

	.category-name {
		font-weight: 600;
		text-transform: capitalize;
		flex: 1;
	}

	.category-stats {
		display: flex;
		gap: 0.75rem;
		font-size: 0.875rem;
		color: var(--text-secondary);
	}

	.enabled-count {
		color: var(--success);
		font-weight: 500;
	}

	.expand-icon {
		margin-left: 0.5rem;
		font-size: 0.75rem;
		color: var(--text-secondary);
	}

	.blocklist-list {
		display: flex;
		flex-direction: column;
		gap: 0;
		border-top: 1px solid var(--border);
	}

	.blocklist-item {
		display: flex;
		align-items: flex-start;
		gap: 1rem;
		padding: 0.75rem 1rem;
		background: var(--bg-card);
		cursor: pointer;
		border-bottom: 1px solid var(--border);
	}

	.blocklist-item:last-child {
		border-bottom: none;
	}

	.blocklist-item:hover {
		background: var(--bg);
	}

	.blocklist-info {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.blocklist-info .name {
		font-weight: 500;
	}

	.blocklist-info .meta {
		font-size: 0.875rem;
		color: var(--text-secondary);
	}

	.blocklist-info .description {
		font-size: 0.8rem;
		color: var(--text-secondary);
		opacity: 0.8;
	}

	.add-rule-form {
		display: flex;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.add-rule-form input {
		flex: 1;
		padding: 0.5rem 1rem;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 0.25rem;
		color: var(--text);
	}

	.add-rule-form select {
		padding: 0.5rem 1rem;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 0.25rem;
		color: var(--text);
	}

	.rules-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.rule-item {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 0.5rem;
		background: var(--bg);
		border-radius: 0.25rem;
	}

	.rule-type {
		padding: 0.25rem 0.5rem;
		border-radius: 0.25rem;
		font-size: 0.75rem;
		text-transform: uppercase;
	}

	.rule-allow {
		background: var(--success);
		color: white;
	}

	.rule-deny {
		background: var(--danger);
		color: white;
	}

	.rule-domain {
		flex: 1;
	}

	.log-controls {
		display: flex;
		align-items: center;
		gap: 1rem;
	}

	.logs-table {
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

	.domain {
		font-family: monospace;
		word-break: break-all;
	}

	tr.blocked {
		background: rgba(239, 68, 68, 0.1);
	}

	.status-blocked {
		color: var(--danger);
	}

	.status-allowed {
		color: var(--success);
	}

	.empty {
		color: var(--text-secondary);
		text-align: center;
		padding: 2rem;
	}

	.btn {
		padding: 0.5rem 1rem;
		border-radius: 0.25rem;
		font-size: 0.875rem;
		font-weight: 500;
		cursor: pointer;
		border: none;
		transition: all 0.2s;
	}

	.btn-primary {
		background: var(--primary);
		color: white;
	}

	.btn-outline {
		background: transparent;
		border: 1px solid var(--border);
		color: var(--text);
	}

	.btn-danger {
		background: var(--danger);
		color: white;
	}

	.btn-small {
		padding: 0.25rem 0.5rem;
		font-size: 0.75rem;
	}

	@media (max-width: 768px) {
		.stats-section {
			grid-template-columns: 1fr;
		}

		.setup-grid {
			grid-template-columns: 1fr;
		}
	}
</style>
