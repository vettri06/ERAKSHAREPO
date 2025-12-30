import type { NetworkInterface } from '@/types';
import { cn } from '@/lib/utils';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

interface InterfaceSelectorProps {
  interfaces: NetworkInterface[];
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  className?: string;
}

export function InterfaceSelector({
  interfaces,
  value,
  onChange,
  disabled,
  className,
}: InterfaceSelectorProps) {
  return (
    <Select value={value} onValueChange={onChange} disabled={disabled}>
      <SelectTrigger className={cn('w-full bg-secondary/50', className)}>
        <SelectValue placeholder="Select network interface" />
      </SelectTrigger>
      <SelectContent>
        {interfaces.map(iface => {
          return (
            <SelectItem key={iface.name} value={iface.name}>
              <div className="flex items-center gap-2">
                <span className="font-mono">{iface.displayName}</span>
                <span className="text-xs text-muted-foreground">({iface.ip})</span>
                {iface.isDefault && (
                  <span className="text-xs text-primary">default</span>
                )}
              </div>
            </SelectItem>
          );
        })}
      </SelectContent>
    </Select>
  );
}