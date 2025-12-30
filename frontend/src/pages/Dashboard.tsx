import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { dashboardApi, scanApi, networkApi, devicesApi } from '@/services/api';
import type { DashboardStats, ActivityItem, ScanStatus, NetworkInterface, ScanMode } from '@/types';
import { Button } from '@/components/ui/button';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ScanProgress } from '@/components/ScanProgress';
import { InterfaceSelector } from '@/components/InterfaceSelector';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

const scanModes: { value: ScanMode; label: string; description: string }[] = [
  { value: 'quick', label: 'Quick', description: '~1 min' },
  { value: 'deep', label: 'Deep', description: '~5 min' },
  { value: 'comprehensive', label: 'Full', description: '~15 min' },
];

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [selectedMode, setSelectedMode] = useState<ScanMode>('quick');
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    const loadData = async () => {
      try {
        const [statsRes, activityRes, interfacesRes, statusRes] = await Promise.all([
          dashboardApi.getStats(),
          dashboardApi.getActivity(),
          networkApi.getInterfaces(),
          scanApi.getStatus(),
        ]);
        if (statsRes.success) setStats(statsRes.data!);
        if (activityRes.success) setActivity(activityRes.data!);
        if (interfacesRes.success) setInterfaces(interfacesRes.data!);
        if (statusRes.success) setScanStatus(statusRes.data!);
      } catch (error) {
        console.error('[Dashboard] Error loading data:', error);
      } finally {
        setIsLoading(false);
      }
    };
    loadData();
    // Poll for general dashboard updates every 5 seconds
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (interfaces.length > 0 && !selectedInterface) {
      setSelectedInterface(interfaces[0].name);
    }
  }, [interfaces, selectedInterface]);

  useEffect(() => {
    if (!scanStatus || scanStatus.status !== 'running') return;
    const interval = setInterval(async () => {
      const res = await scanApi.getStatus();
      if (res.success) {
        setScanStatus(res.data!);
        const activityRes = await dashboardApi.getActivity();
        if (activityRes.success) setActivity(activityRes.data!);
        if (res.data!.status === 'completed') {
          toast({
            title: 'Scan Complete',
            description: `Found ${res.data!.vulnerabilitiesFound} vulnerabilities across ${res.data!.devicesScanned} devices.`,
          });
          const statsRes = await dashboardApi.getStats();
          if (statsRes.success) setStats(statsRes.data!);
        }
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [scanStatus?.status, toast]);

  const handleStartScan = async () => {
    const res = await scanApi.start({ mode: selectedMode, interface: selectedInterface });
    if (res.success) {
      setScanStatus(res.data!);
      toast({
        title: 'Scan Started',
        description: `${selectedMode.charAt(0).toUpperCase() + selectedMode.slice(1)} scan initiated on ${selectedInterface}`,
      });
    }
  };

  const handleStopScan = async () => {
    const res = await scanApi.stop();
    if (res.success) {
      setScanStatus(res.data!);
      toast({ title: 'Scan Stopped' });
    }
  };

  const formatTimeAgo = (timestamp: string) => {
    const diff = Date.now() - new Date(timestamp).getTime();
    const mins = Math.floor(diff / 60000);
    const hours = Math.floor(mins / 60);
    const days = Math.floor(hours / 24);
    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (mins > 0) return `${mins}m ago`;
    return 'Just now';
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <p className="text-muted-foreground font-mono">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  const isScanning = scanStatus?.status === 'running';

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display cyber-heading text-glow-blue">Dashboard</h1>
          <p className="text-muted-foreground text-sm">
            Network security overview and scan controls
          </p>
        </div>
        {stats?.lastScanTime && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            Last scan: {formatTimeAgo(stats.lastScanTime)}
          </div>
        )}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Link to="/devices" className="cyber-card p-4 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-muted-foreground uppercase tracking-wide">Total Devices</p>
              <p className="text-3xl font-bold text-foreground mt-1">{stats?.totalDevices || 0}</p>
            </div>
            {/* Icon Removed */}
          </div>
        </Link>

        <Link to="/devices?filter=vulnerable" className="cyber-card p-4 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-muted-foreground uppercase tracking-wide">Vulnerable</p>
              <p className="text-3xl font-bold text-destructive mt-1">{stats?.vulnerableDevices || 0}</p>
            </div>
            {/* Icon Removed */}
          </div>
        </Link>

        <Link to="/vulnerabilities" className="cyber-card p-4 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-muted-foreground uppercase tracking-wide">Critical CVEs</p>
              <p className="text-3xl font-bold text-destructive mt-1">{stats?.criticalVulnerabilities || 0}</p>
            </div>
            {/* Icon Removed */}
          </div>
        </Link>

        <div className="cyber-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-muted-foreground uppercase tracking-wide">Active Scans</p>
              <p className="text-3xl font-bold text-primary mt-1">{isScanning ? 1 : 0}</p>
            </div>
            {/* Icon Removed */}
          </div>
        </div>

        <div className="cyber-card p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-muted-foreground uppercase tracking-wide">Anomalies</p>
              <p className="text-3xl font-bold text-warning mt-1">{stats?.anomaliesDetected || 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Scan */}
      <div className="cyber-card p-6">
        <h2 className="text-lg font-display cyber-heading mb-4 flex items-center gap-2">
          Quick Scan
        </h2>
        {isScanning && scanStatus ? (
          <div className="space-y-4">
            <ScanProgress
              progress={scanStatus.progress}
              currentDevice={scanStatus.currentDevice}
              devicesScanned={scanStatus.devicesScanned}
              totalDevices={scanStatus.totalDevices}
              eta={scanStatus.eta}
              isScanning={true}
            />
            <div className="flex items-center gap-2">
              <Button variant="destructive" onClick={handleStopScan}>
                Stop Scan
              </Button>
              <span className="text-sm text-muted-foreground">
                Mode: {scanStatus.mode}  Interface: {scanStatus.interface}
              </span>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-muted-foreground mb-2 block">Network Interface</label>
                <InterfaceSelector
                  interfaces={interfaces}
                  value={selectedInterface}
                  onChange={setSelectedInterface}
                />
              </div>
              <div>
                <label className="text-sm text-muted-foreground mb-2 block">Scan Mode</label>
                <div className="flex gap-2">
                  {scanModes.map(mode => {
                    return (
                      <Button
                        key={mode.value}
                        variant={selectedMode === mode.value ? 'default' : 'outline'}
                        className={cn(
                          'flex-1',
                          selectedMode === mode.value && 'glow-blue'
                        )}
                        onClick={() => setSelectedMode(mode.value)}
                      >
                        {mode.label}
                        <span className="text-xs ml-1 opacity-70">{mode.description}</span>
                      </Button>
                    );
                  })}
                </div>
              </div>
            </div>
            <Button onClick={handleStartScan} className="glow-blue">
              Start Scan
            </Button>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Chart */}
        <div className="cyber-card p-6">
          <h2 className="text-lg font-display cyber-heading mb-4 flex items-center gap-2">
            Vulnerability Severity
          </h2>
          <div className="space-y-3">
            {[
              { label: 'Critical', value: stats?.criticalVulnerabilities || 0, severity: 'critical' as const },
              { label: 'High', value: stats?.highVulnerabilities || 0, severity: 'high' as const },
              { label: 'Medium', value: stats?.mediumVulnerabilities || 0, severity: 'medium' as const },
              { label: 'Low', value: stats?.lowVulnerabilities || 0, severity: 'low' as const },
            ].map(item => {
              const total = (stats?.criticalVulnerabilities || 0) + (stats?.highVulnerabilities || 0) + 
                           (stats?.mediumVulnerabilities || 0) + (stats?.lowVulnerabilities || 0);
              const percentage = total > 0 ? (item.value / total) * 100 : 0;
              return (
                <div key={item.severity} className="flex items-center gap-3">
                  <SeverityBadge severity={item.severity} size="sm" className="w-24" />
                  <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
                    <div
                      className={cn(
                        'h-full transition-all duration-500',
                        item.severity === 'critical' && 'bg-destructive',
                        item.severity === 'high' && 'bg-orange-500',
                        item.severity === 'medium' && 'bg-warning',
                        item.severity === 'low' && 'bg-info',
                      )}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                  <span className="text-sm font-mono text-foreground w-8 text-right">{item.value}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Recent Activity */}
        <div className="cyber-card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-display cyber-heading flex items-center gap-2">
              Recent Activity
            </h2>
            <Link to="/logs" className="text-sm text-primary hover:underline flex items-center gap-1">
              View all
            </Link>
          </div>
          <div className="space-y-3">
            {activity.slice(0, 5).map(item => (
              <div key={item.id} className="flex items-start gap-3 p-2 rounded hover:bg-secondary/30 transition-colors">
                <div className={cn(
                  'w-2 h-2 rounded-full mt-1.5 flex-shrink-0',
                  item.severity === 'critical' && 'bg-destructive',
                  item.severity === 'high' && 'bg-orange-500',
                  item.type === 'scan_completed' && 'bg-accent',
                  item.type === 'scan_started' && 'bg-primary',
                  item.type === 'device_found' && 'bg-info',
                  !item.severity && item.type !== 'scan_completed' && item.type !== 'scan_started' && item.type !== 'device_found' && 'bg-muted-foreground',
                )} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-foreground truncate">{item.message}</p>
                  <p className="text-xs text-muted-foreground">{formatTimeAgo(item.timestamp)}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
