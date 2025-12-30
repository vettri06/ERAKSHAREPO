import type { Severity, RiskLevel } from '@/types';
import { cn } from '@/lib/utils';

interface SeverityBadgeProps {
  severity: Severity | RiskLevel;
  showIcon?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}
const severityConfig = {
  critical: {
    bg: 'bg-destructive/20',
    border: 'border-destructive/50',
    text: 'text-destructive',
    glow: 'glow-red',
    label: 'Critical',
  },
  high: {
    bg: 'bg-orange-500/20',
    border: 'border-orange-500/50',
    text: 'text-orange-400',
    glow: '',
    label: 'High',
  },
  medium: {
    bg: 'bg-warning/20',
    border: 'border-warning/50',
    text: 'text-warning',
    glow: '',
    label: 'Medium',
  },
  low: {
    bg: 'bg-info/20',
    border: 'border-info/50',
    text: 'text-info',
    glow: '',
    label: 'Low',
  },
  info: {
    bg: 'bg-muted',
    border: 'border-muted-foreground/30',
    text: 'text-muted-foreground',
    glow: '',
    label: 'Info',
  },
  none: {
    bg: 'bg-accent/20',
    border: 'border-accent/50',
    text: 'text-accent',
    glow: 'glow-green',
    label: 'Secure',
  },
};
const sizeClasses = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-2.5 py-1 text-xs',
  lg: 'px-3 py-1.5 text-sm',
};
export function SeverityBadge({
  severity,
  showIcon = true,
  size = 'md',
  className,
}: SeverityBadgeProps) {
  const config = severityConfig[severity] || severityConfig.info;
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border font-mono uppercase tracking-wide',
        config.bg,
        config.border,
        config.text,
        config.glow,
        sizeClasses[size],
        className
      )}
    >
      <span>{config.label}</span>
    </span>
  );
}