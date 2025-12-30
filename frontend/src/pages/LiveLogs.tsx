import { useEffect, useState } from 'react';
import { logsApi } from '@/services/api';
import type { LogEntry } from '@/types';
import { LogViewer } from '@/components/LogViewer';
import { Button } from '@/components/ui/button';

export default function LiveLogs() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    logsApi.getAll().then(res => {
      if (res.success) setLogs(res.data!);
      setIsLoading(false);
    });
  }, []);

  useEffect(() => {
    const interval = setInterval(async () => {
      const res = await logsApi.getRecent(50);
      if (res.success) setLogs(res.data!);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleClear = async () => {
    await logsApi.clear();
    setLogs([]);
  };

  const handleDownload = async () => {
    await logsApi.downloadDebugLog();
  };

  if (isLoading) {
    return <div className="flex items-center justify-center h-64"><div className="w-12 h-12 border-2 border-primary border-t-transparent rounded-full animate-spin" /></div>;
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display cyber-heading text-glow-blue flex items-center gap-2">
            Live Logs
          </h1>
          <p className="text-muted-foreground text-sm">Real-time system and scan logs</p>
        </div>
        <Button variant="outline" size="sm" onClick={handleDownload} className="gap-2">
          Download Full Log
        </Button>
      </div>
      <LogViewer logs={logs} onClear={handleClear} maxHeight="calc(100vh - 220px)" />
    </div>
  );
}