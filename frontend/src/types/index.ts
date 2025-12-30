export interface Device {
  id: string;
  ip: string;
  mac: string;
  vendor: string;
  type: DeviceType;
  hostname?: string;
  ports: Port[];
  vulnerabilities: Vulnerability[];
  riskLevel: RiskLevel;
  lastSeen: string;
  firstSeen: string;
  os?: string;
  services: string[];
  aiConfidence?: number;
  osPrediction?: {
    os: string;
    version?: string;
    confidence: number;
  };
  detectedVendor?: string;
  mlFeatures?: string[];
}
export type DeviceType = 
  | 'router' 
  | 'switch' 
  | 'camera' 
  | 'sensor' 
  | 'thermostat' 
  | 'smart_speaker' 
  | 'smart_tv' 
  | 'computer' 
  | 'phone' 
  | 'printer' 
  | 'nas' 
  | 'unknown'
  | 'cant_determine';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';
export interface Port {
  number: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
  service?: string;
  product?: string;
  version?: string;
}
export interface Vulnerability {
  id: string;
  cve_id: string;
  severity: Severity;
  cvss_score: number;
  description: string;
  remediation: string;
  download_link?: string;
  affected_devices: string[];
  references: string[];
  published_date: string;
  last_modified: string;
  aiRiskScore?: number;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  category?: 'vulnerability' | 'misconfiguration' | 'exposure';
  status?: 'confirmed' | 'potential' | 'unverified';
  version_checked?: string;
}
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface ScanStatus {
  id: string;
  status: 'idle' | 'running' | 'completed' | 'failed' | 'paused';
  mode: ScanMode;
  progress: number;
  currentDevice?: string;
  devicesScanned: number;
  totalDevices: number;
  vulnerabilitiesFound: number;
  startTime?: string;
  endTime?: string;
  eta?: string;
  interface: string;
}
export type ScanMode = 'quick' | 'deep' | 'comprehensive';
export interface ScanConfig {
  mode: ScanMode;
  interface: string;
  portRange?: string;
  timeout?: number;
  excludeHosts?: string[];
}
export interface ScanReport {
  id: string;
  scanId?: string;
  timestamp: string;
  duration?: number;
  mode: ScanMode;
  interface?: string;
  summary: {
    totalDevices: number;
    newDevices: number;
    vulnerableDevices: number;
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  devices?: Device[];
  vulnerabilities?: Vulnerability[];
}
export interface NetworkInterface {
  name: string;
  displayName: string;
  ip: string;
  netmask: string;
  mac: string;
  type: 'ethernet' | 'wifi' | 'virtual';
  status: 'up' | 'down';
  isDefault: boolean;
}
export interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  message: string;
  source?: string;
  details?: Record<string, unknown>;
}
export type LogLevel = 'debug' | 'info' | 'warning' | 'error';
export interface User {
  id: string;
  username: string;
  role: 'admin' | 'viewer';
}
export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
}
export interface LoginCredentials {
  username: string;
  password: string;
}
export interface Settings {
  apiEndpoint: string;
  defaultInterface: string;
  autoRefreshInterval: number;
  logRetentionDays: number;
  aiModelEnabled: boolean;
  aiModelStatus: 'online' | 'offline' | 'loading';
}
export interface DashboardStats {
  totalDevices: number;
  vulnerableDevices: number;
  activeScans: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  mediumVulnerabilities: number;
  lowVulnerabilities: number;
  anomaliesDetected: number;
  lastScanTime?: string;
}
export interface ActivityItem {
  id: string;
  type: 'scan_started' | 'scan_completed' | 'device_found' | 'vulnerability_detected' | 'alert';
  message: string;
  timestamp: string;
  severity?: Severity;
}
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}
