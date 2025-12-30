import { cn } from '@/lib/utils';

interface ScanProgressProps {
  progress: number;
  currentDevice?: string;
  devicesScanned: number;
  totalDevices: number;
  eta?: string;
  isScanning: boolean;
  className?: string;
}
export function ScanProgress({
  progress,
  currentDevice,
  devicesScanned,
  totalDevices,
  eta,
  isScanning,
  className,
}: ScanProgressProps) {
  return (
    <div className={cn('space-y-3', className)}>
      {}
      <div className="relative h-3 bg-secondary rounded-full overflow-hidden border border-border">
        <div
          className="absolute inset-y-0 left-0 bg-gradient-to-r from-primary to-accent transition-all duration-500 ease-out"
          style={{ width: `${progress}%` }}
        />
        {isScanning && (
          <div
            className="absolute inset-y-0 w-20 bg-gradient-to-r from-transparent via-foreground/20 to-transparent animate-scan"
            style={{ left: `${progress - 10}%` }}
          />
        )}
      </div>
      {}
      <div className="flex items-center justify-between text-sm font-mono">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">
            {devicesScanned} / {totalDevices} devices
          </span>
        </div>
        <div className="flex items-center gap-4">
          {eta && isScanning && (
            <span className="text-muted-foreground">ETA: {eta}</span>
          )}
          <span className={cn(
            'font-bold',
            progress === 100 ? 'text-accent text-glow-green' : 'text-primary text-glow-blue'
          )}>
            {progress}%
          </span>
        </div>
      </div>
      {}
      {currentDevice && isScanning && (
        <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
          <span className="text-foreground">Scanning:</span>
          <span className="text-primary">{currentDevice}</span>
          <span className="terminal-cursor" />
        </div>
      )}
    </div>
  );
}