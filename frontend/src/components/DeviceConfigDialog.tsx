import { useEffect, useState } from 'react';
import type { Device, DeviceType } from '@/types';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Command, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { vendorsApi, devicesApi } from '@/services/api';

interface Props {
  device: Device;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUpdated?: (updated: Partial<Device>) => void;
}

export function DeviceConfigDialog({ device, open, onOpenChange, onUpdated }: Props) {
  const [vendorQuery, setVendorQuery] = useState('');
  const [vendorOptions, setVendorOptions] = useState<string[]>([]);
  const [selectedVendor, setSelectedVendor] = useState(device.vendor || '');
  const [selectedType, setSelectedType] = useState<DeviceType>(device.type);
  const [isSaving, setIsSaving] = useState(false);
  
  const [showVendorList, setShowVendorList] = useState(false);
  const [showTypeList, setShowTypeList] = useState(false);
  const [typeQuery, setTypeQuery] = useState('');

  const deviceTypes: DeviceType[] = ['router','switch','camera','sensor','thermostat','smart_speaker','smart_tv','computer','phone','printer','nas','unknown', 'cant_determine'];

  useEffect(() => {
    const v = device.vendor || '';
    setSelectedVendor(v);
    setVendorQuery(v);
    
    const t = device.type;
    setSelectedType(t);
    setTypeQuery(t ? t.replace('_', ' ') : '');
  }, [device]);

  useEffect(() => {
    let active = true;
    if (vendorQuery) {
        vendorsApi.search(vendorQuery, false).then(res => {
        if (active && res.success) {
            setVendorOptions(res.data || []);
        }
        });
    } else {
        setVendorOptions([]);
    }
    return () => { active = false; };
  }, [vendorQuery]);

  const handleSave = async () => {
    setIsSaving(true);
    const payload: { vendor?: string; type?: string } = {};
    if (selectedVendor && selectedVendor !== device.vendor) payload.vendor = selectedVendor;
    if (selectedType && selectedType !== device.type) payload.type = selectedType;
    
    if (Object.keys(payload).length === 0) {
      onOpenChange(false);
      setIsSaving(false);
      return;
    }

    const res = await devicesApi.updateConfig(device.id, payload);
    setIsSaving(false);
    if (res.success) {
      onUpdated?.({ vendor: selectedVendor, type: selectedType });
      onOpenChange(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="overflow-visible sm:max-w-[425px]" onOpenAutoFocus={(e) => e.preventDefault()}>
        <DialogHeader>
          <DialogTitle>Edit Device</DialogTitle>
        </DialogHeader>
        
        <div className="space-y-6 py-4">
          
          <div className="relative z-20">
            <label className="text-sm text-muted-foreground mb-2 block">Vendor</label>
            <Command shouldFilter={false} className="overflow-visible bg-transparent border rounded-md">
              <CommandInput 
                placeholder="Search or enter vendor..."
                value={vendorQuery}
                onValueChange={(val) => {
                  setVendorQuery(val);
                  setSelectedVendor(val);
                  setShowVendorList(true);
                }}
                onFocus={() => setShowVendorList(true)}
                onBlur={() => setTimeout(() => setShowVendorList(false), 200)}
                className="border-none focus:ring-0"
              />
              {showVendorList && vendorOptions.length > 0 && (
                <div className="absolute top-full left-0 w-full bg-popover border rounded-md shadow-md mt-1 z-50">
                  <CommandList className="max-h-[200px] overflow-y-auto">
                    <CommandGroup>
                      {vendorOptions.map(v => (
                        <CommandItem
                          key={v}
                          value={v}
                          onSelect={(currentValue) => {
                            setVendorQuery(currentValue);
                            setSelectedVendor(currentValue);
                            setShowVendorList(false);
                          }}
                        >
                          {v}
                        </CommandItem>
                      ))}
                    </CommandGroup>
                  </CommandList>
                </div>
              )}
            </Command>
          </div>

          <div className="relative z-10">
            <label className="text-sm text-muted-foreground mb-2 block">Device Type</label>
            <Command shouldFilter={false} className="overflow-visible bg-transparent border rounded-md">
                <CommandInput 
                    placeholder="Search type..."
                    value={typeQuery}
                    onValueChange={(val) => {
                        setTypeQuery(val);
                        const typeVal = val.replace(' ', '_') as DeviceType;
                        setSelectedType(typeVal);
                        setShowTypeList(true);
                    }}
                    onFocus={() => setShowTypeList(true)}
                    onBlur={() => setTimeout(() => setShowTypeList(false), 200)}
                    className="border-none focus:ring-0"
                />
                {showTypeList && (
                    <div className="absolute top-full left-0 w-full bg-popover border rounded-md shadow-md mt-1 z-50">
                        <CommandList className="max-h-[200px] overflow-y-auto">
                             <CommandGroup>
                                {deviceTypes
                                    .filter(t => t.replace('_', ' ').toLowerCase().includes(typeQuery.toLowerCase()))
                                    .map(t => (
                                        <CommandItem
                                            key={t}
                                            value={t.replace('_', ' ')}
                                            onSelect={(currentValue) => {
                                                setTypeQuery(currentValue);
                                                setSelectedType(t);
                                                setShowTypeList(false);
                                            }}
                                        >
                                            {t.replace('_', ' ')}
                                        </CommandItem>
                                    ))
                                }
                             </CommandGroup>
                        </CommandList>
                    </div>
                )}
            </Command>
          </div>

        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSaving}>Cancel</Button>
          <Button onClick={handleSave} className="glow-blue" disabled={isSaving}>Save</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
