<script lang="ts">
	import { page } from '$app/stores';
	import { onMount, onDestroy } from 'svelte';
	import {
		getProfile,
		getBlocklists,
		updateProfile,
		deleteProfile,
		pauseFiltering,
		resumeFiltering,
		getProfileLogs,
		getProfileStats,
		createRule,
		deleteRule,
		profileLogin,
		type ProfileDetails,
		type ProfileStats,
		type Blocklist,
		type QueryLog
	} from '$lib/api';
	import { toasts } from '$lib/stores';
	import { goto } from '$app/navigation';

	let profile: ProfileDetails | null = null;
	let blocklists: Blocklist[] = [];
	let logs: QueryLog[] = [];
	let detailedStats: ProfileStats | null = null;
	let loading = true;
	let error = '';
	let showDetailedStats = false;
	let statsHours = 24; // Time period for stats
	let loadingStats = false;

	// Helper functions for bar chart calculations
	function getBarWidth(count: number, items: { count: number }[]): number {
		const max = Math.max(...items.map(i => i.count));
		return max > 0 ? (count / max) * 100 : 0;
	}

	function getHourCount(hour: number): number {
		if (!detailedStats) return 0;
		const data = detailedStats.queries_by_hour.find(h => h.hour === hour);
		return data?.count || 0;
	}

	function getHourBarHeight(hour: number): number {
		if (!detailedStats || detailedStats.queries_by_hour.length === 0) return 0;
		const max = Math.max(...detailedStats.queries_by_hour.map(h => h.count));
		const count = getHourCount(hour);
		return max > 0 ? (count / max) * 100 : 0;
	}

	function getBlocklistName(blocklistId: string): string {
		const bl = blocklists.find(b => b.id === blocklistId);
		return bl?.name || blocklistId;
	}

	async function loadStats(hours: number) {
		statsHours = hours;
		loadingStats = true;
		const statsResult = await getProfileStats(profileName, hours, authToken);
		detailedStats = statsResult.data || null;
		loadingStats = false;
	}

	function formatBlocklistSource(item: { blocklist_id: string | null; blocklist_name: string | null; blocklist_category: string | null }): string {
		if (!item.blocklist_id) return 'Unknown';
		if (item.blocklist_id === 'deny_rule') return 'Custom Rule';
		if (item.blocklist_id === 'preset') return 'Preset';
		return item.blocklist_name || item.blocklist_id;
	}

	// Auth state
	let needsPassword = false;
	let passwordInput = '';
	let authToken: string | undefined = undefined;

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

	// Delete confirmation
	let showDeleteConfirm = false;
	let deleteConfirmName = '';
	let deleting = false;

	// Pause countdown timer
	let countdownInterval: ReturnType<typeof setInterval> | null = null;
	let remainingSeconds = 0;

	$: profileName = $page.params.name;

	// Format remaining time as "Xm Ys"
	function formatCountdown(seconds: number): string {
		if (seconds <= 0) return '0s';
		const mins = Math.floor(seconds / 60);
		const secs = seconds % 60;
		if (mins > 0) {
			return `${mins}m ${secs}s`;
		}
		return `${secs}s`;
	}

	// Start or update countdown timer
	function startCountdown() {
		stopCountdown();
		if (!profile?.is_filtering_paused || !profile?.filtering_paused_until) {
			remainingSeconds = 0;
			return;
		}

		const until = new Date(profile.filtering_paused_until).getTime();
		const now = Date.now();

		// If already expired, just set to 0 and don't auto-reload (prevents loop)
		if (until <= now) {
			remainingSeconds = 0;
			return;
		}

		const updateRemaining = () => {
			const now = Date.now();
			remainingSeconds = Math.max(0, Math.floor((until - now) / 1000));

			if (remainingSeconds <= 0) {
				stopCountdown();
				// Auto-refresh when timer expires
				loadData();
			}
		};

		updateRemaining();
		countdownInterval = setInterval(updateRemaining, 1000);
	}

	function stopCountdown() {
		if (countdownInterval) {
			clearInterval(countdownInterval);
			countdownInterval = null;
		}
	}

	// Watch for pause state changes
	$: if (profile?.is_filtering_paused) {
		startCountdown();
	} else {
		stopCountdown();
		remainingSeconds = 0;
	}

	onDestroy(() => {
		stopCountdown();
	});

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

		const profileResult = await getProfile(profileName, authToken);

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
		const [blocklistsResult, logsResult, statsResult] = await Promise.all([
			getBlocklists(),
			getProfileLogs(profileName, { limit: 50 }, authToken),
			getProfileStats(profileName, 24, authToken)
		]);

		loading = false;
		profile = profileResult.data || null;
		blocklists = blocklistsResult.data?.blocklists || [];
		logs = logsResult.data?.logs || [];
		detailedStats = statsResult.data || null;
	}

	async function handlePasswordSubmit() {
		// Call login endpoint to get a secure token
		const loginResult = await profileLogin(profileName, passwordInput);
		if (loginResult.error) {
			toasts.error(loginResult.error);
			passwordInput = '';
			return;
		}

		// Store the token for subsequent requests
		authToken = loginResult.data?.token;
		passwordInput = '';

		// Now load the profile data with the token
		await loadData();
	}

	async function toggleBlocklist(blocklistId: string) {
		if (!profile) return;

		const newBlocklists = profile.blocklists.includes(blocklistId)
			? profile.blocklists.filter((id) => id !== blocklistId)
			: [...profile.blocklists, blocklistId];

		const result = await updateProfile(profileName, { blocklists: newBlocklists }, authToken);
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

		const result = await updateProfile(profileName, { blocklists: newBlocklists }, authToken);
		if (result.error) {
			toasts.error(result.error);
		} else {
			profile.blocklists = newBlocklists;
			toasts.success('Blocklists updated');
		}
	}

	async function handlePause(minutes: number) {
		const result = await pauseFiltering(profileName, minutes, authToken);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success(`Filtering paused for ${minutes} minutes`);
			await loadData();
		}
	}

	async function handleResume() {
		const result = await resumeFiltering(profileName, authToken);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Filtering resumed');
			await loadData();
		}
	}

	async function handleAddRule() {
		if (!newRuleDomain.trim()) return;

		const result = await createRule(profileName, newRuleDomain.trim(), newRuleType, authToken);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Rule added');
			newRuleDomain = '';
			await loadData();
		}
	}

	async function handleDeleteRule(ruleId: string) {
		const result = await deleteRule(profileName, ruleId, authToken);
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
		}, authToken);
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
		const result = await updateProfile(profileName, { password: newPassword || null }, authToken);
		savingPassword = false;

		if (result.error) {
			toasts.error(result.error);
		} else {
			if (newPassword) {
				toasts.success('Password set successfully');
				// Get a new token with the new password
				const loginResult = await profileLogin(profileName, newPassword);
				authToken = loginResult.data?.token;
			} else {
				toasts.success('Password removed');
				authToken = undefined;
			}
			newPassword = '';
			confirmPassword = '';
			showPasswordSection = false;
			await loadData();
		}
	}

	async function handleRemovePassword() {
		savingPassword = true;
		const result = await updateProfile(profileName, { password: null }, authToken);
		savingPassword = false;

		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Password removed');
			authToken = undefined;
			await loadData();
		}
	}

	async function handleDeleteProfile() {
		if (deleteConfirmName !== profileName) {
			toasts.error('Profile name does not match');
			return;
		}

		deleting = true;
		const result = await deleteProfile(profileName, authToken);
		deleting = false;

		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Profile deleted');
			goto('/');
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
			<div class="filtering-toggle">
				<label class="toggle-switch">
					<input
						type="checkbox"
						checked={!profile.is_filtering_paused}
						on:change={() => profile.is_filtering_paused ? handleResume() : handlePause(30)}
					/>
					<span class="toggle-slider"></span>
				</label>
				{#if profile.is_filtering_paused}
					<div class="toggle-status paused">
						<span class="status-text">Paused: {formatCountdown(remainingSeconds)}</span>
					</div>
				{:else}
					<span class="toggle-status active">Filtering enabled</span>
				{/if}
				{#if !profile.is_filtering_paused}
					<div class="pause-buttons">
						<button class="btn btn-small btn-outline" on:click={() => handlePause(5)}>5m</button>
						<button class="btn btn-small btn-outline" on:click={() => handlePause(15)}>15m</button>
						<button class="btn btn-small btn-outline" on:click={() => handlePause(30)}>30m</button>
					</div>
				{/if}
			</div>
		</header>

		<!-- Stats Overview -->
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
			{#if detailedStats?.avg_response_time_ms}
				<div class="stat-card">
					<div class="stat-value">{detailedStats.avg_response_time_ms}ms</div>
					<div class="stat-label">Avg Response</div>
				</div>
			{/if}
		</section>

		<!-- Detailed Stats Toggle -->
		<section class="card">
			<div class="card-header">
				<h2>Statistics</h2>
				<div class="stats-controls">
					<div class="time-selector">
						<button class="time-btn" class:active={statsHours === 1} on:click={() => loadStats(1)}>1h</button>
						<button class="time-btn" class:active={statsHours === 4} on:click={() => loadStats(4)}>4h</button>
						<button class="time-btn" class:active={statsHours === 24} on:click={() => loadStats(24)}>24h</button>
						<button class="time-btn" class:active={statsHours === 168} on:click={() => loadStats(168)}>7d</button>
					</div>
					<button class="btn btn-small btn-outline" on:click={() => showDetailedStats = !showDetailedStats}>
						{showDetailedStats ? 'Hide' : 'Show'}
					</button>
				</div>
			</div>

			{#if loadingStats}
				<div class="stats-loading">Loading stats...</div>
			{:else if showDetailedStats && detailedStats}
				<div class="stats-details">
					<!-- Top Blocked Domains with Source -->
					{#if detailedStats.top_blocked_domains.length > 0}
						<div class="stats-subsection wide">
							<h4>Top Blocked Domains</h4>
							<div class="blocked-domains-table">
								{#each detailedStats.top_blocked_domains.slice(0, 8) as item}
									<div class="blocked-row">
										<span class="blocked-domain">{item.domain}</span>
										<span class="blocked-source" class:custom-rule={item.blocklist_id === 'deny_rule'}>
											{formatBlocklistSource(item)}
											{#if item.blocklist_category}
												<span class="source-category">{item.blocklist_category}</span>
											{/if}
										</span>
										<span class="blocked-count">{item.count}</span>
									</div>
								{/each}
							</div>
						</div>
					{/if}

					<!-- Top Allowed Domains -->
					{#if detailedStats.top_allowed_domains.length > 0}
						<div class="stats-subsection">
							<h4>Top Allowed Domains</h4>
							<div class="domain-list">
								{#each detailedStats.top_allowed_domains.slice(0, 6) as item}
									<div class="domain-row">
										<span class="domain-name allowed">{item.domain}</span>
										<span class="domain-count">{item.count.toLocaleString()}</span>
									</div>
								{/each}
							</div>
						</div>
					{/if}

					<!-- Top Blocklists -->
					{#if detailedStats.top_blocklists.length > 0}
						<div class="stats-subsection">
							<h4>Blocking Sources</h4>
							<div class="blocklist-stats">
								{#each detailedStats.top_blocklists.slice(0, 5) as bl}
									<div class="bar-row">
										<div class="bar-label-wrap">
											<span class="bar-label" title={bl.blocklist_id}>
												{bl.blocklist_id === 'deny_rule' ? 'Custom Rules' : bl.name}
											</span>
											{#if bl.category}
												<span class="bar-category">{bl.category}</span>
											{/if}
										</div>
										<div class="bar-container">
											<div class="bar blocked" style="width: {getBarWidth(bl.count, detailedStats.top_blocklists)}%"></div>
										</div>
										<span class="bar-value">{bl.count.toLocaleString()}</span>
									</div>
								{/each}
							</div>
						</div>
					{/if}

					<!-- Queries by Hour -->
					{#if detailedStats.queries_by_hour.length > 0}
						<div class="stats-subsection">
							<h4>Activity by Hour</h4>
							<div class="hourly-chart">
								{#each Array(24) as _, hour}
									<div class="hour-bar" title="{hour}:00 - {getHourCount(hour)} queries">
										<div
											class="hour-fill"
											style="height: {getHourBarHeight(hour)}%"
										></div>
									</div>
								{/each}
							</div>
							<div class="hour-labels">
								<span>0</span>
								<span>6</span>
								<span>12</span>
								<span>18</span>
								<span>23</span>
							</div>
						</div>
					{/if}
				</div>
				{#if detailedStats.total_queries === 0}
					<p class="stats-empty">No query data yet. Statistics will appear once DNS queries are processed through this profile.</p>
				{/if}
			{:else if !showDetailedStats}
				<p class="stats-hint">Click "Show Details" to see query types, top domains, active blocklists, and hourly activity.</p>
			{/if}
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

		<!-- Danger Zone -->
		<section class="card danger-zone">
			<h2>Danger Zone</h2>
			{#if !showDeleteConfirm}
				<div class="danger-item">
					<div>
						<h4>Delete this profile</h4>
						<p>Once deleted, all settings, rules, and logs for this profile will be permanently removed.</p>
					</div>
					<button class="btn btn-danger" on:click={() => showDeleteConfirm = true}>
						Delete Profile
					</button>
				</div>
			{:else}
				<div class="delete-confirm">
					<p class="warning-text">This action cannot be undone. Please type <strong>{profileName}</strong> to confirm.</p>
					<input
						type="text"
						bind:value={deleteConfirmName}
						placeholder="Type profile name to confirm"
					/>
					<div class="confirm-actions">
						<button
							class="btn btn-danger"
							on:click={handleDeleteProfile}
							disabled={deleting || deleteConfirmName !== profileName}
						>
							{deleting ? 'Deleting...' : 'I understand, delete this profile'}
						</button>
						<button class="btn btn-outline" on:click={() => { showDeleteConfirm = false; deleteConfirmName = ''; }}>
							Cancel
						</button>
					</div>
				</div>
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

	.pause-controls {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.filtering-toggle {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.toggle-switch {
		position: relative;
		display: inline-block;
		width: 50px;
		height: 26px;
	}

	.toggle-switch input {
		opacity: 0;
		width: 0;
		height: 0;
	}

	.toggle-slider {
		position: absolute;
		cursor: pointer;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background-color: var(--warning);
		transition: 0.3s;
		border-radius: 26px;
	}

	.toggle-slider:before {
		position: absolute;
		content: "";
		height: 20px;
		width: 20px;
		left: 3px;
		bottom: 3px;
		background-color: white;
		transition: 0.3s;
		border-radius: 50%;
	}

	.toggle-switch input:checked + .toggle-slider {
		background-color: var(--success);
	}

	.toggle-switch input:checked + .toggle-slider:before {
		transform: translateX(24px);
	}

	.toggle-status {
		font-size: 0.875rem;
		font-weight: 500;
	}

	.toggle-status.active {
		color: var(--success);
	}

	.toggle-status.paused {
		color: var(--warning);
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.pause-buttons {
		display: flex;
		gap: 0.25rem;
		margin-left: 0.5rem;
		padding-left: 0.75rem;
		border-left: 1px solid var(--border);
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

	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.danger-zone {
		border-color: var(--danger);
		margin-top: 2rem;
	}

	.danger-zone h2 {
		color: var(--danger);
	}

	.danger-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 1rem;
	}

	.danger-item h4 {
		margin: 0 0 0.25rem 0;
	}

	.danger-item p {
		margin: 0;
		color: var(--text-secondary);
		font-size: 0.875rem;
	}

	.delete-confirm {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.delete-confirm input {
		padding: 0.75rem 1rem;
		background: var(--bg);
		border: 1px solid var(--danger);
		border-radius: 0.5rem;
		color: var(--text);
		font-size: 1rem;
	}

	.warning-text {
		color: var(--danger);
		margin: 0;
	}

	.confirm-actions {
		display: flex;
		gap: 0.5rem;
	}

	/* Detailed Stats Styles */
	.stats-details {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 1.5rem;
		margin-top: 1rem;
	}

	.stats-subsection {
		background: var(--bg);
		border-radius: 0.5rem;
		padding: 1rem;
	}

	.stats-subsection h4 {
		margin: 0 0 0.75rem 0;
		font-size: 0.9rem;
		color: var(--text-secondary);
	}

	.stats-bar-chart {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.bar-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.bar-label {
		width: 60px;
		font-size: 0.8rem;
		font-family: monospace;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.bar-container {
		flex: 1;
		height: 16px;
		background: var(--bg-secondary);
		border-radius: 4px;
		overflow: hidden;
	}

	.bar {
		height: 100%;
		background: var(--primary);
		border-radius: 4px;
		transition: width 0.3s ease;
	}

	.bar.blocked {
		background: var(--danger);
	}

	.bar-value {
		width: 60px;
		font-size: 0.8rem;
		text-align: right;
		color: var(--text-secondary);
	}

	.domain-list {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	.domain-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 0.25rem 0;
		border-bottom: 1px solid var(--border);
	}

	.domain-row:last-child {
		border-bottom: none;
	}

	.domain-name {
		font-family: monospace;
		font-size: 0.8rem;
		color: var(--success);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 70%;
	}

	.domain-list.blocked .domain-name {
		color: var(--danger);
	}

	.domain-count {
		font-size: 0.8rem;
		color: var(--text-secondary);
	}

	.blocklist-stats .bar-label {
		width: 100px;
	}

	/* Hourly Activity Chart */
	.hourly-chart {
		display: flex;
		align-items: flex-end;
		height: 60px;
		gap: 2px;
	}

	.hour-bar {
		flex: 1;
		height: 100%;
		background: var(--bg-secondary);
		border-radius: 2px 2px 0 0;
		display: flex;
		flex-direction: column;
		justify-content: flex-end;
	}

	.hour-fill {
		background: var(--primary);
		border-radius: 2px 2px 0 0;
		transition: height 0.3s ease;
	}

	.hour-labels {
		display: flex;
		justify-content: space-between;
		font-size: 0.7rem;
		color: var(--text-secondary);
		margin-top: 0.25rem;
	}

	.stats-hint {
		color: var(--text-secondary);
		font-size: 0.9rem;
		margin: 0;
	}

	.stats-empty {
		color: var(--text-secondary);
		font-size: 0.9rem;
		text-align: center;
		padding: 2rem;
		margin: 0;
		background: var(--bg);
		border-radius: 0.5rem;
	}

	.stats-controls {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}

	.time-selector {
		display: flex;
		gap: 0.25rem;
		background: var(--bg);
		padding: 0.25rem;
		border-radius: 0.5rem;
	}

	.time-btn {
		padding: 0.35rem 0.75rem;
		border: none;
		background: transparent;
		color: var(--text-secondary);
		cursor: pointer;
		border-radius: 0.25rem;
		font-size: 0.8rem;
		font-weight: 500;
		transition: all 0.2s;
	}

	.time-btn:hover {
		background: var(--bg-secondary);
		color: var(--text);
	}

	.time-btn.active {
		background: var(--primary);
		color: white;
	}

	.stats-loading {
		text-align: center;
		padding: 2rem;
		color: var(--text-secondary);
	}

	.stats-subsection.wide {
		grid-column: span 2;
	}

	.blocked-domains-table {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.blocked-row {
		display: grid;
		grid-template-columns: 1fr auto auto;
		gap: 1rem;
		align-items: center;
		padding: 0.5rem 0.75rem;
		background: rgba(239, 68, 68, 0.1);
		border-radius: 0.25rem;
		border-left: 3px solid var(--danger);
	}

	.blocked-domain {
		font-family: monospace;
		font-size: 0.85rem;
		color: var(--danger);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.blocked-source {
		font-size: 0.75rem;
		color: var(--text-secondary);
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}

	.blocked-source.custom-rule {
		color: var(--warning);
	}

	.source-category {
		background: var(--bg-secondary);
		padding: 0.15rem 0.4rem;
		border-radius: 0.25rem;
		font-size: 0.7rem;
		text-transform: uppercase;
	}

	.blocked-count {
		font-weight: 600;
		font-size: 0.85rem;
		min-width: 2rem;
		text-align: right;
	}

	.domain-name.allowed {
		color: var(--success);
	}

	.bar-label-wrap {
		display: flex;
		flex-direction: column;
		gap: 0.15rem;
		min-width: 100px;
	}

	.bar-category {
		font-size: 0.65rem;
		color: var(--text-secondary);
		text-transform: uppercase;
	}

	@media (max-width: 768px) {
		.stats-section {
			grid-template-columns: repeat(2, 1fr);
		}

		.setup-grid {
			grid-template-columns: 1fr;
		}

		.stats-details {
			grid-template-columns: 1fr;
		}

		.stats-subsection.wide {
			grid-column: span 1;
		}

		.stats-controls {
			flex-direction: column;
			align-items: stretch;
			gap: 0.5rem;
		}

		.time-selector {
			justify-content: center;
		}

		.blocked-row {
			grid-template-columns: 1fr auto;
		}

		.blocked-source {
			display: none;
		}
	}
</style>
