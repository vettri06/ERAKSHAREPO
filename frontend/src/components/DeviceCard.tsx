import type { Device } from '@/types';
import { cn } from '@/lib/utils';
import { SeverityBadge } from './SeverityBadge';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { DeviceConfigDialog } from './DeviceConfigDialog';
interface DeviceCardProps {
  device: Device;
  onClick?: () => void;
  selected?: boolean;
  className?: string;
}
export function DeviceCard({ device, onClick, selected, className }: DeviceCardProps) {
  const [open, setOpen] = useState(false);
  const [localDevice, setLocalDevice] = useState<Device>(device);
  const openPorts = localDevice.ports.filter(p => p.state === 'open');
  return (
    <div
      onClick={onClick}
      className={cn(
        'cyber-card p-4 cursor-pointer transition-all duration-200',
        selected && 'border-primary glow-blue',
        className
      )}
    >
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0 space-y-2">
          <div className="flex items-start justify-between gap-2">
            <div>
              <h3 className="font-mono text-sm text-foreground truncate">
                {localDevice.hostname || localDevice.ip}
              </h3>
              <p className="text-xs text-muted-foreground font-mono">
                {localDevice.ip}  {localDevice.vendor}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button size="sm" variant="outline" onClick={(e) => { e.stopPropagation(); setOpen(true); }}>Edit</Button>
              <SeverityBadge severity={localDevice.riskLevel} size="sm" />
            </div>
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="px-2 py-0.5 bg-secondary rounded text-muted-foreground font-mono">
              {localDevice.type.replace('_', ' ')}
            </span>
            <span className="px-2 py-0.5 bg-secondary rounded text-muted-foreground font-mono">
              {openPorts.length} open ports
            </span>
            {localDevice.vulnerabilities.length > 0 && (
              <span className="px-2 py-0.5 bg-destructive/20 rounded text-destructive font-mono">
                {localDevice.vulnerabilities.length} CVE{localDevice.vulnerabilities.length !== 1 && 's'}
              </span>
            )}
          </div>
          {}
          {openPorts.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {openPorts.slice(0, 5).map(port => (
                <span
                  key={`${port.number}-${port.protocol}`}
                  className="px-1.5 py-0.5 text-xs bg-primary/10 border border-primary/30 rounded text-primary font-mono"
                >
                  {port.number}/{port.protocol}
                </span>
              ))}
              {openPorts.length > 5 && (
                <span className="px-1.5 py-0.5 text-xs text-muted-foreground font-mono">
                  +{openPorts.length - 5} more
                </span>
              )}
            </div>
          )}
          {}
          {(localDevice.aiConfidence || localDevice.osPrediction) && (
            <div className="pt-2 border-t border-border/50 mt-2 space-y-1">
              {localDevice.osPrediction && (
                <div className="flex justify-between items-center text-xs">
                  <span className="text-muted-foreground">AI OS Prediction:</span>
                  <span className="font-mono text-primary">
                    {localDevice.osPrediction.os} <span className="text-muted-foreground/70">({(localDevice.osPrediction.confidence * 100).toFixed(0)}%)</span>
                  </span>
                </div>
              )}
              {localDevice.aiConfidence && (
                <div className="flex justify-between items-center text-xs">
                  <span className="text-muted-foreground">Device Confidence:</span>
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-16 bg-secondary rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-primary transition-all"
                        style={{ width: `${localDevice.aiConfidence * 100}%` }}
                      />
                    </div>
                    <span className="font-mono">{(localDevice.aiConfidence * 100).toFixed(0)}%</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      <DeviceConfigDialog
        device={localDevice}
        open={open}
        onOpenChange={setOpen}
        onUpdated={(upd) => setLocalDevice({ ...localDevice, ...upd })}
      />
    </div>
  );
}
