import type {
  Device,
  Vulnerability,
  ScanStatus,
  ScanConfig,
  ScanReport,
  NetworkInterface,
  LogEntry,
  DashboardStats,
  ActivityItem,
  Settings,
  LoginCredentials,
  User,
  ApiResponse,
} from '@/types';
import {
  mockReports,
  mockLogs,
  mockActivity,
  mockSettings,
} from './mockData';
const API_URL = '/api';
async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<ApiResponse<T>> {
  try {
    // Add no-cache headers to prevent browser caching of API responses
    const finalOptions = {
      ...options,
      headers: {
        ...options?.headers,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    };

    console.log(`[API] Request: ${endpoint}`, finalOptions);
    const response = await fetch(`${API_URL}${endpoint}`, finalOptions);
    if (!response.ok) {
        console.error(`[API] HTTP Error ${response.status} for ${endpoint}`);
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    console.log(`[API] Response from ${endpoint}:`, data);
    return data;
  } catch (error) {
    console.error(`[API] Error for ${endpoint}:`, error);
    return { success: false, error: String(error) };
  }
}
export const authApi = {
  login: async (credentials: LoginCredentials): Promise<ApiResponse<{ user: User; token: string }>> => {
    return fetchApi('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
    });
  },
  logout: async (): Promise<ApiResponse<void>> => {
    return { success: true };
  },
  validateToken: async (token: string): Promise<ApiResponse<User>> => {
    if (token) return { success: true, data: { id: 'user-001', username: 'admin', role: 'admin' } };
    return { success: false, error: 'Invalid token' };
  },
  changePassword: async (oldPassword: string, newPassword: string): Promise<ApiResponse<void>> => {
    return { success: true, message: 'Password changed successfully' };
  },
};
export const dashboardApi = {
  getStats: async (): Promise<ApiResponse<DashboardStats>> => {
    return fetchApi('/dashboard/stats');
  },
  getActivity: async (): Promise<ApiResponse<ActivityItem[]>> => {
    return fetchApi('/dashboard/activity');
  },
};
export const devicesApi = {
  getAll: async (): Promise<ApiResponse<Device[]>> => {
    return fetchApi('/devices');
  },
  getById: async (id: string): Promise<ApiResponse<Device>> => {
    return fetchApi(`/devices/${id}`);
  },
  updateConfig: async (id: string, payload: { vendor?: string; type?: string }): Promise<ApiResponse<{ ip: string }>> => {
    return fetchApi(`/devices/${id}/config`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  },
  delete: async (id: string): Promise<ApiResponse<void>> => {
    return fetchApi(`/devices/${id}`, { method: 'DELETE' });
  },
  exportCsv: async (): Promise<Blob> => {
    const response = await devicesApi.getAll();
    if (!response.success || !response.data) return new Blob([]);
    const devices = response.data;
    const headers = ['IP', 'MAC', 'Vendor', 'Type', 'Hostname', 'Risk Level', 'Open Ports', 'Vulnerabilities'];
    const rows = devices.map(d => [
      d.ip,
      d.mac,
      d.vendor,
      d.type,
      d.hostname || 'N/A',
      d.riskLevel,
      d.ports.filter(p => p.state === 'open').map(p => p.number).join(';'),
      d.vulnerabilities.length.toString(),
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    return new Blob([csv], { type: 'text/csv' });
  },
};
export const vendorsApi = {
  search: async (query: string, refresh?: boolean): Promise<ApiResponse<string[]>> => {
    const params: Record<string, string> = {};
    if (query) params.query = query;
    if (refresh) params.refresh = 'true';
    const qs = new URLSearchParams(params).toString();
    return fetchApi(`/vendors/search?${qs}`);
  },
};
export const networkApi = {
  getInterfaces: async (): Promise<ApiResponse<NetworkInterface[]>> => {
    return fetchApi('/interfaces');
  },
};
export const scanApi = {
  getStatus: async (): Promise<ApiResponse<ScanStatus>> => {
    return fetchApi('/scan/status');
  },
  start: async (config: ScanConfig): Promise<ApiResponse<ScanStatus>> => {
    return fetchApi('/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    });
  },
  stop: async (): Promise<ApiResponse<ScanStatus>> => {
    const res = await fetchApi<unknown>('/scan/stop', { method: 'POST' });
    if (res.success) {
        return scanApi.getStatus();
    }
    return { success: false, error: res.error };
  },
  pause: async (): Promise<ApiResponse<ScanStatus>> => {
    return { success: false, error: "Pause not supported" };
  },
};
export const vulnerabilitiesApi = {
  getAll: async (): Promise<ApiResponse<Vulnerability[]>> => {
    const devicesRes = await devicesApi.getAll();
    if (devicesRes.success && devicesRes.data) {
        const vulns = devicesRes.data.flatMap(d => d.vulnerabilities);
        return { success: true, data: vulns };
    }
    return { success: false, error: "Could not fetch devices" };
  },
  getBySeverity: async (severity: string): Promise<ApiResponse<Vulnerability[]>> => {
     const res = await vulnerabilitiesApi.getAll();
     if (res.success && res.data) {
         return { success: true, data: res.data.filter(v => v.severity === severity) };
     }
     return res;
  },
};
export const reportsApi = {
  getAll: async (): Promise<ApiResponse<ScanReport[]>> => {
    return fetchApi('/reports');
  },
  getById: async (id: string): Promise<ApiResponse<ScanReport>> => {
    return fetchApi(`/reports/${id}`);
  },
  delete: async (id: string): Promise<ApiResponse<void>> => {
    return fetchApi(`/reports/${id}`, { method: 'DELETE' });
  },
  downloadJson: async (id: string): Promise<Blob> => {
    const response = await fetch(`${API_URL}/reports/${id}`);
    if (!response.ok) {
        throw new Error('Report not found');
    }
    const data = await response.json();
    return new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
  },
  downloadPdf: async (id: string): Promise<Blob> => {
    const response = await fetch(`${API_URL}/reports/${id}/pdf`);
    if (!response.ok) {
        throw new Error('Report/PDF not found');
    }
    return response.blob();
  },
};
export const logsApi = {
  getAll: async (): Promise<ApiResponse<LogEntry[]>> => {
    return fetchApi('/logs');
  },
  getRecent: async (count: number = 50): Promise<ApiResponse<LogEntry[]>> => {
    const res = await fetchApi<LogEntry[]>('/logs');
    if (res.success && res.data) {
        return { success: true, data: res.data.slice(0, count) };
    }
    return res;
  },
  clear: async (): Promise<ApiResponse<void>> => {
    return { success: true };
  },
  downloadDebugLog: async (): Promise<void> => {
    const response = await fetch(`${API_URL}/debug/log`);
    if (!response.ok) {
        console.error('Failed to download log');
        return;
    }
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'backend_debug.log';
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },
};
export const settingsApi = {
  get: async (): Promise<ApiResponse<Settings>> => {
    return { success: true, data: mockSettings };
  },
  update: async (settings: Partial<Settings>): Promise<ApiResponse<Settings>> => {
    const updated = { ...mockSettings, ...settings };
    return { success: true, data: updated };
  },
  exportConfig: async (): Promise<Blob> => {
    return new Blob([JSON.stringify(mockSettings, null, 2)], { type: 'application/json' });
  },
  importConfig: async (config: Settings): Promise<ApiResponse<Settings>> => {
    return { success: true, data: config };
  },
};
