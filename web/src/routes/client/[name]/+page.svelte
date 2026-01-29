<script lang="ts">
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import {
		getClient,
		getBlocklists,
		updateClient,
		pauseFiltering,
		resumeFiltering,
		getClientLogs,
		createRule,
		deleteRule,
		type ClientDetails,
		type Blocklist,
		type QueryLog
	} from '$lib/api';
	import { toasts } from '$lib/stores';

	let client: ClientDetails | null = null;
	let blocklists: Blocklist[] = [];
	let logs: QueryLog[] = [];
	let loading = true;
	let error = '';

	// Form state
	let newRuleDomain = '';
	let newRuleType: 'allow' | 'deny' = 'allow';
	let showBlockedOnly = false;

	$: clientName = $page.params.name;

	onMount(async () => {
		await loadData();
	});

	async function loadData() {
		loading = true;
		error = '';

		const [clientResult, blocklistsResult, logsResult] = await Promise.all([
			getClient(clientName),
			getBlocklists(),
			getClientLogs(clientName, { limit: 50 })
		]);

		loading = false;

		if (clientResult.error) {
			error = clientResult.error;
			return;
		}

		client = clientResult.data || null;
		blocklists = blocklistsResult.data?.blocklists || [];
		logs = logsResult.data?.logs || [];
	}

	async function toggleBlocklist(blocklistId: string) {
		if (!client) return;

		const newBlocklists = client.blocklists.includes(blocklistId)
			? client.blocklists.filter((id) => id !== blocklistId)
			: [...client.blocklists, blocklistId];

		const result = await updateClient(clientName, { blocklists: newBlocklists });
		if (result.error) {
			toasts.error(result.error);
		} else {
			client.blocklists = newBlocklists;
			toasts.success('Blocklists updated');
		}
	}

	async function handlePause(minutes: number) {
		const result = await pauseFiltering(clientName, minutes);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success(`Filtering paused for ${minutes} minutes`);
			await loadData();
		}
	}

	async function handleResume() {
		const result = await resumeFiltering(clientName);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Filtering resumed');
			await loadData();
		}
	}

	async function handleAddRule() {
		if (!newRuleDomain.trim()) return;

		const result = await createRule(clientName, newRuleDomain.trim(), newRuleType);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Rule added');
			newRuleDomain = '';
			await loadData();
		}
	}

	async function handleDeleteRule(ruleId: string) {
		const result = await deleteRule(clientName, ruleId);
		if (result.error) {
			toasts.error(result.error);
		} else {
			toasts.success('Rule deleted');
			await loadData();
		}
	}

	async function refreshLogs() {
		const result = await getClientLogs(clientName, {
			limit: 50,
			blocked: showBlockedOnly
		});
		if (result.data) {
			logs = result.data.logs;
		}
	}

	function copyToClipboard(text: string) {
		navigator.clipboard.writeText(text);
		toasts.success('Copied to clipboard');
	}
</script>

<svelte:head>
	<title>{clientName} - FilterDNS</title>
</svelte:head>

{#if loading}
	<div class="loading">Loading...</div>
{:else if error}
	<div class="error">
		<h2>Error</h2>
		<p>{error}</p>
		<a href="/">Go back home</a>
	</div>
{:else if client}
	<div class="client-page">
		<header class="page-header">
			<div>
				<h1>{client.name}</h1>
				<p class="endpoint">{client.dns_endpoint}</p>
			</div>
			{#if client.is_filtering_paused}
				<div class="pause-banner">
					<span>Filtering paused until {new Date(client.filtering_paused_until || '').toLocaleTimeString()}</span>
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
				<div class="stat-value">{client.stats.total_queries.toLocaleString()}</div>
				<div class="stat-label">Queries (24h)</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">{client.stats.blocked_queries.toLocaleString()}</div>
				<div class="stat-label">Blocked</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">{client.stats.blocked_percentage}%</div>
				<div class="stat-label">Block Rate</div>
			</div>
		</section>

		<!-- Setup Instructions -->
		<section class="card">
			<h2>Setup Instructions</h2>
			<div class="setup-grid">
				<div class="setup-item">
					<h4>DNS-over-HTTPS (DoH)</h4>
					<code on:click={() => copyToClipboard(client?.doh_url || '')}>{client.doh_url}</code>
				</div>
				<div class="setup-item">
					<h4>DNS-over-TLS (DoT)</h4>
					<code on:click={() => copyToClipboard(client?.dot_hostname || '')}>{client.dot_hostname}</code>
				</div>
			</div>
		</section>

		<!-- Blocklists -->
		<section class="card">
			<h2>Blocklists</h2>
			<div class="blocklist-list">
				{#each blocklists as bl}
					<label class="blocklist-item">
						<input
							type="checkbox"
							checked={client.blocklists.includes(bl.id)}
							on:change={() => toggleBlocklist(bl.id)}
						/>
						<div class="blocklist-info">
							<span class="name">{bl.name}</span>
							<span class="meta">{bl.category} - {bl.domain_count.toLocaleString()} domains</span>
						</div>
					</label>
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
			{#if client.rules.length > 0}
				<div class="rules-list">
					{#each client.rules as rule}
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

	.client-page {
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

	.blocklist-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.blocklist-item {
		display: flex;
		align-items: center;
		gap: 1rem;
		padding: 0.75rem;
		background: var(--bg);
		border-radius: 0.25rem;
		cursor: pointer;
	}

	.blocklist-info {
		display: flex;
		flex-direction: column;
	}

	.blocklist-info .name {
		font-weight: 500;
	}

	.blocklist-info .meta {
		font-size: 0.875rem;
		color: var(--text-secondary);
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
