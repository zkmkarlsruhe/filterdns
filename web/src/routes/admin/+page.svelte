<script lang="ts">
	import { onMount } from 'svelte';
	import {
		adminLogin,
		adminLogout,
		adminGetClients,
		adminGetStats,
		type AdminClient,
		type GlobalStats
	} from '$lib/api';
	import { isAdmin, toasts } from '$lib/stores';

	let password = '';
	let loggingIn = false;
	let clients: AdminClient[] = [];
	let stats: GlobalStats | null = null;
	let loading = true;

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
		clients = [];
		stats = null;
	}

	async function loadData() {
		loading = true;
		const [clientsResult, statsResult] = await Promise.all([adminGetClients(), adminGetStats()]);

		if (clientsResult.data) {
			clients = clientsResult.data.clients;
		}
		if (statsResult.data) {
			stats = statsResult.data;
		}
		loading = false;
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
						<div class="stat-value">{stats.total_clients}</div>
						<div class="stat-label">Total Clients</div>
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

			<section class="card">
				<h2>All Clients</h2>
				{#if clients.length > 0}
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
								{#each clients as client}
									<tr>
										<td>
											<a href="/client/{client.name}">{client.name}</a>
											{#if client.has_password}
												<span class="badge">Password</span>
											{/if}
										</td>
										<td>{client.total_queries_24h.toLocaleString()}</td>
										<td>{client.blocked_percentage}%</td>
										<td>
											{#if client.is_filtering_paused}
												<span class="status-paused">Paused</span>
											{:else}
												<span class="status-active">Active</span>
											{/if}
										</td>
										<td>{new Date(client.created_at).toLocaleDateString()}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{:else}
					<p class="empty">No clients yet</p>
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

	input {
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
		width: 100%;
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
	}
</style>
