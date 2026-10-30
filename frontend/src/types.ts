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

export interface SystemHealth {
  status: string;
  platform: string;
  uptime_seconds: number;
  sqlite: {
    wal_mode: boolean;
    path: string;
  };
  memory: {
    rss_mb: number;
    vms_mb: number;
    system_used_percent: number;
    system_available_mb: number;
  };
  engines: Record<string, { status: string; description: string }>;
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
