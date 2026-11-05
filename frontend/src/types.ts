export type TabId = 
  | 'dashboard' 
  | 'recon' 
  | 'intel' 
  | 'guard' 
  | 'graph' 
  | 'stix' 
  | 'audit' 
  | 'settings'
  | 'profile'
  | 'reports';

export interface EngineInfo {
  name?: string;
  status: string;
  tier?: string;
  description: string;
  latency_ms?: number;
  connected?: boolean;
}

export interface SystemHealth {
  status: string;
  platform: string;
  version?: string;
  uptime_seconds: number;
  database?: any;
  sqlite?: {
    wal_mode: boolean;
    path: string;
    status?: string;
  };
  memory: {
    rss_mb: number;
    vms_mb: number;
    system_used_percent: number;
    system_available_mb: number;
  };
  engines: Record<string, EngineInfo>;
}

export interface OperatorProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  clearance: string;
  organization: string;
  avatar_text: string;
  permissions: string[];
  client_ip: string;
  mfa_enabled: boolean;
  hardware_key_bound: boolean;
  default_scope: string;
  token_fingerprint: string;
}
