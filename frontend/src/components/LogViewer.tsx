import { useRef, useEffect, useState } from 'react';
import type { LogEntry, LogLevel } from '@/types';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

interface LogViewerProps {
  logs: LogEntry[];
  onClear?: () => void;
  className?: string;
  maxHeight?: string;
}
const logLevelColors: Record<LogLevel, string> = {
  debug: 'text-muted-foreground',
  info: 'text-info',
  warning: 'text-warning',
  error: 'text-destructive',
};
const logLevelLabels: Record<LogLevel, string> = {
  debug: 'DBG',
  info: 'INF',
  warning: 'WRN',
  error: 'ERR',
};
export function LogViewer({ logs, onClear, className, maxHeight = '400px' }: LogViewerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isPaused, setIsPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState<LogLevel | 'all'>('all');
  const filteredLogs = filter === 'all' 
    ? logs 
    : logs.filter(log => log.level === filter);
  useEffect(() => {
    if (autoScroll && !isPaused && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll, isPaused]);
  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
    setAutoScroll(isAtBottom);
  };
  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { 
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };
  return (
    <div className={cn('flex flex-col rounded-lg border border-border bg-card overflow-hidden', className)}>
      {}
      <div className="flex items-center justify-between px-3 py-2 bg-secondary/50 border-b border-border">
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsPaused(!isPaused)}
            className="h-7 px-2 text-xs"
          >
            {isPaused ? (
              <>
                Resume
              </>
            ) : (
              <>
                Pause
              </>
            )}
          </Button>
          {onClear && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onClear}
              className="h-7 px-2 text-xs text-muted-foreground hover:text-destructive"
            >
              Clear
            </Button>
          )}
        </div>
        <div className="flex items-center gap-1">
          {(['all', 'debug', 'info', 'warning', 'error'] as const).map(level => (
            <Button
              key={level}
              variant={filter === level ? 'secondary' : 'ghost'}
              size="sm"
              onClick={() => setFilter(level)}
              className={cn(
                'h-6 px-2 text-xs uppercase',
                filter === level && 'border border-border'
              )}
            >
              {level === 'all' ? 'All' : logLevelLabels[level]}
            </Button>
          ))}
        </div>
      </div>
      {}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="font-mono text-xs overflow-y-auto bg-background/50 scanline"
        style={{ maxHeight }}
      >
        {filteredLogs.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-muted-foreground">
            No logs to display
          </div>
        ) : (
          <div className="p-2 space-y-0.5">
            {filteredLogs.map(log => (
              <div
                key={log.id}
                className="flex items-start gap-2 py-0.5 hover:bg-secondary/30 px-1 rounded"
              >
                <span className="text-muted-foreground flex-shrink-0">
                  [{formatTimestamp(log.timestamp)}]
                </span>
                <span className={cn('flex-shrink-0 font-bold', logLevelColors[log.level])}>
                  [{logLevelLabels[log.level]}]
                </span>
                {log.source && (
                  <span className="text-primary/70 flex-shrink-0">
                    [{log.source}]
                  </span>
                )}
                <span className="text-foreground break-all">{log.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      {}
      {!autoScroll && (
        <Button
          variant="secondary"
          size="sm"
          onClick={() => {
            if (containerRef.current) {
              containerRef.current.scrollTop = containerRef.current.scrollHeight;
              setAutoScroll(true);
            }
          }}
          className="absolute bottom-14 right-4 h-7 text-xs shadow-lg"
        >
          Scroll to latest
        </Button>
      )}
    </div>
  );
}