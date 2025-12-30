import { useEffect, useState } from 'react';
import { networkApi, scanApi } from '@/services/api';
import type { NetworkInterface, ScanStatus, ScanMode } from '@/types';
import { InterfaceSelector } from '@/components/InterfaceSelector';
import { ScanProgress } from '@/components/ScanProgress';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export default function NetworkDiscovery() {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    Promise.all([networkApi.getInterfaces(), scanApi.getStatus()]).then(([ifRes, statusRes]) => {
      if (ifRes.success) {
        setInterfaces(ifRes.data!);
        if (ifRes.data!.length > 0 && !selectedInterface) {
          setSelectedInterface(ifRes.data![0].name);
        }
      }
      if (statusRes.success) setScanStatus(statusRes.data!);
      setIsLoading(false);
    });
  }, []);

  useEffect(() => {
    if (!scanStatus || scanStatus.status !== 'running') return;
    const interval = setInterval(async () => {
      const res = await scanApi.getStatus();
      if (res.success) setScanStatus(res.data!);
    }, 1000);
    return () => clearInterval(interval);
  }, [scanStatus?.status]);

  const handleStart = async () => {
    const res = await scanApi.start({ mode: 'deep', interface: selectedInterface });
    if (res.success) setScanStatus(res.data!);
  };

  const handleStop = async () => {
    const res = await scanApi.stop();
    if (res.success) setScanStatus(res.data!);
  };

  const isScanning = scanStatus?.status === 'running';

  if (isLoading) {
    return <div className="flex items-center justify-center h-64"><div className="w-12 h-12 border-2 border-primary border-t-transparent rounded-full animate-spin" /></div>;
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-display cyber-heading text-glow-blue">Network Discovery</h1>
        <p className="text-muted-foreground text-sm">Scan network for IoT devices</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="cyber-card p-6">
          <h2 className="text-lg font-display mb-4">Network Interfaces</h2>
          <div className="space-y-3">
            {interfaces.map(iface => {
              return (
                <div key={iface.name} className={cn('p-3 rounded border', selectedInterface === iface.name ? 'border-primary bg-primary/10' : 'border-border bg-secondary/30')} onClick={() => setSelectedInterface(iface.name)}>
                  <div className="flex items-center gap-3">
                    {/* Icon Removed */}
                    <div>
                      <p className="font-mono text-sm">{iface.displayName}</p>
                      <p className="text-xs text-muted-foreground">{iface.ip}  {iface.mac}</p>
                    </div>
                    <div className={cn('ml-auto w-2 h-2 rounded-full', iface.status === 'up' ? 'status-online' : 'status-offline')} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="cyber-card p-6">
          <h2 className="text-lg font-display mb-4">Scan Control</h2>
          {isScanning && scanStatus ? (
            <div className="space-y-4">
              <ScanProgress progress={scanStatus.progress} currentDevice={scanStatus.currentDevice} devicesScanned={scanStatus.devicesScanned} totalDevices={scanStatus.totalDevices} eta={scanStatus.eta} isScanning={true} />
              <Button variant="destructive" onClick={handleStop}>Stop</Button>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">Selected: <span className="text-primary">{selectedInterface}</span></p>
              <Button onClick={handleStart} className="glow-blue">Start Discovery</Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
