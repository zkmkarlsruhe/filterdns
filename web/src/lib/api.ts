// API client for FilterDNS

const API_BASE = '/api';

interface ApiResponse<T> {
	data?: T;
	error?: string;
	status?: number;
}

async function request<T>(
	method: string,
	endpoint: string,
	body?: unknown,
	authToken?: string
): Promise<ApiResponse<T>> {
	try {
		const headers: Record<string, string> = {
			'Content-Type': 'application/json'
		};
		if (authToken) {
			headers['Authorization'] = `Bearer ${authToken}`;
		}

		const response = await fetch(`${API_BASE}${endpoint}`, {
			method,
			headers,
			body: body ? JSON.stringify(body) : undefined,
			credentials: 'include'
		});

		const data = await response.json();

		if (!response.ok) {
			return { error: data.error || `HTTP ${response.status}`, status: response.status };
		}

		return { data, status: response.status };
	} catch (err) {
		return { error: err instanceof Error ? err.message : 'Network error' };
	}
}

// Blocklists
export async function getBlocklists() {
	return request<{ blocklists: Blocklist[] }>('GET', '/blocklists');
}

// Profiles
export async function createProfile(name: string, password?: string) {
	return request<Profile>('POST', '/profiles', { name, password });
}

export async function profileLogin(name: string, password: string) {
	return request<{ token: string; expires_in: number; profile_id: string }>(
		'POST',
		`/profiles/${name}/login`,
		{ password }
	);
}

export async function profileLogout(name: string, token?: string) {
	return request<{ message: string }>('POST', `/profiles/${name}/logout`, undefined, token);
}

export async function getProfile(name: string, token?: string) {
	return request<ProfileDetails>('GET', `/profiles/${name}`, undefined, token);
}

export async function updateProfile(name: string, data: { password?: string; blocklists?: string[] }, authPassword?: string) {
	return request<{ message: string }>('PUT', `/profiles/${name}`, data, authPassword);
}

export async function deleteProfile(name: string, authPassword?: string) {
	return request<{ message: string }>('DELETE', `/profiles/${name}`, undefined, authPassword);
}

export async function pauseFiltering(name: string, minutes: number, authPassword?: string) {
	return request<{ message: string; paused_until: string }>('POST', `/profiles/${name}/pause`, {
		minutes
	}, authPassword);
}

export async function resumeFiltering(name: string, authPassword?: string) {
	return request<{ message: string }>('POST', `/profiles/${name}/resume`, undefined, authPassword);
}

export async function getProfileLogs(
	name: string,
	params?: { limit?: number; offset?: number; blocked?: boolean; domain?: string },
	authPassword?: string
) {
	const searchParams = new URLSearchParams();
	if (params?.limit) searchParams.set('limit', params.limit.toString());
	if (params?.offset) searchParams.set('offset', params.offset.toString());
	if (params?.blocked) searchParams.set('blocked', 'true');
	if (params?.domain) searchParams.set('domain', params.domain);

	return request<{ logs: QueryLog[] }>('GET', `/profiles/${name}/logs?${searchParams}`, undefined, authPassword);
}

export async function getProfileStats(name: string, hours = 24, authPassword?: string) {
	return request<ProfileStats>('GET', `/profiles/${name}/stats?hours=${hours}`, undefined, authPassword);
}

// Rules
export async function getProfileRules(name: string, authPassword?: string) {
	return request<{ rules: ProfileRule[] }>('GET', `/profiles/${name}/rules`, undefined, authPassword);
}

export async function createRule(name: string, domain: string, ruleType: 'allow' | 'deny', authPassword?: string) {
	return request<ProfileRule>('POST', `/profiles/${name}/rules`, { domain, rule_type: ruleType }, authPassword);
}

export async function deleteRule(name: string, ruleId: string, authPassword?: string) {
	return request<{ message: string }>('DELETE', `/profiles/${name}/rules/${ruleId}`, undefined, authPassword);
}

// Devices
export async function getLinkedDevices(name: string) {
	return request<{ devices: LinkedDevice[] }>('GET', `/profiles/${name}/devices`);
}

export async function linkDevice(name: string, ipAddress: string, label?: string) {
	return request<LinkedDevice>('POST', `/profiles/${name}/devices`, { ip_address: ipAddress, label });
}

export async function unlinkDevice(name: string, deviceId: string) {
	return request<{ message: string }>('DELETE', `/profiles/${name}/devices/${deviceId}`);
}

export async function whoami() {
	return request<{ ip_address: string; hostname: string | null; linked_to: string | null }>(
		'GET',
		'/whoami'
	);
}

// Presets
export async function getPresets() {
	return request<{ presets: Preset[] }>('GET', '/presets');
}

export async function getProfilePresets(name: string) {
	return request<{ presets: Preset[]; preset_ids: string[] }>('GET', `/profiles/${name}/presets`);
}

export async function setProfilePresets(name: string, presetIds: string[]) {
	return request<{ message: string; preset_ids: string[] }>('PUT', `/profiles/${name}/presets`, {
		preset_ids: presetIds
	});
}

export async function addProfilePreset(name: string, presetId: string) {
	return request<{ message: string }>('POST', `/profiles/${name}/presets/${presetId}`);
}

export async function removeProfilePreset(name: string, presetId: string) {
	return request<{ message: string }>('DELETE', `/profiles/${name}/presets/${presetId}`);
}

// Maintenance Mode
export async function getMaintenanceStatus(name: string) {
	return request<{ maintenance_mode: boolean; allowlist: string[] }>('GET', `/profiles/${name}/maintenance`);
}

export async function enableMaintenanceMode(name: string, allowlist?: string[]) {
	return request<{ message: string; maintenance_mode: boolean; allowlist: string[] }>(
		'POST',
		`/profiles/${name}/maintenance`,
		allowlist ? { allowlist } : undefined
	);
}

export async function disableMaintenanceMode(name: string) {
	return request<{ message: string; maintenance_mode: boolean }>('DELETE', `/profiles/${name}/maintenance`);
}

export async function getMaintenanceAllowlist(name: string) {
	return request<{ allowlist: string[] }>('GET', `/profiles/${name}/maintenance/allowlist`);
}

export async function setMaintenanceAllowlist(name: string, allowlist: string[]) {
	return request<{ message: string; allowlist: string[] }>('PUT', `/profiles/${name}/maintenance/allowlist`, {
		allowlist
	});
}

export async function addMaintenanceAllowlistDomain(name: string, domain: string) {
	return request<{ message: string }>('POST', `/profiles/${name}/maintenance/allowlist`, { domain });
}

// Admin
export async function adminLogin(password: string) {
	return request<{ message: string }>('POST', '/admin/login', { password });
}

export async function adminLogout() {
	return request<{ message: string }>('POST', '/admin/logout');
}

export async function adminGetProfiles() {
	return request<{ profiles: AdminProfile[] }>('GET', '/admin/profiles');
}

export async function adminGetStats() {
	return request<GlobalStats>('GET', '/admin/stats');
}

export async function adminGetSettings() {
	return request<AdminSettings>('GET', '/admin/settings');
}

export async function adminUpdateSettings(settings: Partial<AdminSettings>) {
	return request<AdminSettings & { message: string }>('PUT', '/admin/settings', settings);
}

// Types
export interface AdminSettings {
	default_blocklists: string[];
}
export interface Blocklist {
	id: string;
	name: string;
	url: string;
	description: string | null;
	category: string | null;
	domain_count: number;
	last_updated: string | null;
	enabled: boolean;
}

// Admin Blocklist Management
export async function adminAddBlocklist(blocklist: { id: string; name: string; url: string; description?: string; category?: string }) {
	return request<{ id: string; name: string; url: string }>('POST', '/admin/blocklists', blocklist);
}

export async function adminDeleteBlocklist(blocklistId: string) {
	return request<{ message: string }>('DELETE', `/admin/blocklists/${blocklistId}`);
}

export async function adminEnableBlocklist(blocklistId: string) {
	return request<{ message: string }>('POST', `/admin/blocklists/${blocklistId}/enable`);
}

export async function adminDisableBlocklist(blocklistId: string) {
	return request<{ message: string }>('POST', `/admin/blocklists/${blocklistId}/disable`);
}

export interface Profile {
	id: string;
	name: string;
	dns_endpoint: string;
	doh_url: string;
	dot_hostname: string;
	has_password: boolean;
	created_at: string;
}

export interface ProfileDetails extends Profile {
	filtering_paused_until: string | null;
	is_filtering_paused: boolean;
	maintenance_mode: boolean;
	maintenance_allowlist: string[];
	blocklists: string[];
	presets: string[];
	rules: ProfileRule[];
	stats: {
		total_queries: number;
		blocked_queries: number;
		blocked_percentage: number;
		top_blocked_domains: { domain: string; count: number }[];
	};
}

export interface ProfileRule {
	id: string;
	domain: string;
	rule_type: 'allow' | 'deny';
	created_at: string;
}

export interface LinkedDevice {
	id: string;
	ip_address: string;
	hostname: string | null;
	label: string | null;
	created_at: string;
}

export interface QueryLog {
	timestamp: string;
	domain: string;
	query_type: string;
	blocked: boolean;
	blocklist_id: string | null;
	response_time_ms: number | null;
}

export interface ProfileStats {
	hours: number;
	total_queries: number;
	blocked_queries: number;
	allowed_queries: number;
	blocked_percentage: number;
	avg_response_time_ms: number | null;
	top_blocked_domains: {
		domain: string;
		count: number;
		blocklist_id: string | null;
		blocklist_name: string | null;
		blocklist_category: string | null;
	}[];
	top_allowed_domains: { domain: string; count: number }[];
	queries_by_hour: { hour: number; count: number }[];
	top_blocklists: {
		blocklist_id: string;
		name: string;
		category: string | null;
		count: number;
	}[];
}

export interface AdminProfile {
	id: string;
	name: string;
	has_password: boolean;
	is_filtering_paused: boolean;
	total_queries_24h: number;
	blocked_percentage: number;
	created_at: string;
}

export interface GlobalStats {
	total_profiles: number;
	total_queries_today: number;
	total_blocked_today: number;
	blocked_percentage: number;
	active_blocklists: number;
	total_blocked_domains: number;
	loaded_blocklists: string[];
}

export interface Preset {
	id: string;
	name: string;
	description: string | null;
	category: string;
	is_builtin: boolean;
	domain_count: number;
}
