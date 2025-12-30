import { useEffect, useState } from 'react';
import { devicesApi } from '@/services/api';
import type { Device } from '@/types';
import { DeviceCard } from '@/components/DeviceCard';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from '@/hooks/use-toast';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import QRCode from 'qrcode';
export default function DeviceInventory() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [filteredDevices, setFilteredDevices] = useState<Device[]>([]);
  const [search, setSearch] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();
  useEffect(() => {
    const fetchDevices = () => {
      devicesApi.getAll().then(res => {
        if (res.success) {
          setDevices(res.data!);
          // Only set filtered devices initially or if search is empty to avoid overwriting user filter context
          // actually the other useEffect handles filtering based on 'devices' state change,
          // so we just need to update 'devices'.
        }
        setIsLoading(false);
      });
    };

    fetchDevices();
    const interval = setInterval(fetchDevices, 3000);
    return () => clearInterval(interval);
  }, []);
  useEffect(() => {
    const filtered = devices.filter(d =>
      d.ip.includes(search) || d.mac.toLowerCase().includes(search.toLowerCase()) ||
      d.vendor.toLowerCase().includes(search.toLowerCase()) ||
      (d.hostname?.toLowerCase().includes(search.toLowerCase()))
    );
    setFilteredDevices(filtered);
  }, [search, devices]);
  const handleExport = async () => {
    try {
      const doc = new jsPDF();
      doc.setFontSize(22);
      doc.setTextColor(0, 191, 255); 
      doc.text('Device Inventory Report', 14, 20);
      doc.setFontSize(10);
      doc.setTextColor(100);
      doc.text(`Generated on: ${new Date().toLocaleString()}`, 14, 28);
      const tableData = filteredDevices.map(d => [
        d.ip,
        d.mac,
        d.vendor || 'Unknown',
        d.type,
        d.riskLevel.toUpperCase(),
        d.ports.length
      ]);
      autoTable(doc, {
        head: [['IP Address', 'MAC Address', 'Vendor', 'Type', 'Risk', 'Ports']],
        body: tableData,
        startY: 35,
        theme: 'grid',
        headStyles: {
          fillColor: [0, 191, 255], 
          textColor: [255, 255, 255],
          fontStyle: 'bold',
          halign: 'center'
        },
        columnStyles: {
            0: { halign: 'left' },
            4: { halign: 'center' },
            5: { halign: 'center' }
        },
        alternateRowStyles: {
          fillColor: [240, 248, 255] 
        },
        styles: {
          lineColor: [173, 216, 230], 
          lineWidth: 0.1
        }
      });
      const qrData = window.location.href; 
      const qrDataUrl = await QRCode.toDataURL(qrData);
      const pageHeight = doc.internal.pageSize.height;
      doc.setFontSize(12);
      doc.setTextColor(0, 191, 255);
      doc.text('Scan to Login to Dashboard', 14, pageHeight - 55);
      doc.setFontSize(10);
      doc.setTextColor(150);
      doc.text('Use this QR code to access the dashboard from connected devices.', 14, pageHeight - 50);
      doc.addImage(qrDataUrl, 'PNG', 14, pageHeight - 45, 35, 35);
      doc.save('device-inventory-report.pdf');
      toast({ title: 'Export Complete', description: 'Report exported to PDF' });
    } catch (error) {
      console.error('Export failed:', error);
      toast({ title: 'Export Failed', description: 'Could not generate PDF', variant: 'destructive' });
    }
  };
  if (isLoading) {
    return <div className="flex items-center justify-center h-64"><div className="w-12 h-12 border-2 border-primary border-t-transparent rounded-full animate-spin" /></div>;
  }
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display cyber-heading text-glow-blue">Device Inventory</h1>
          <p className="text-muted-foreground text-sm">{devices.length} devices discovered</p>
        </div>
        <Button onClick={handleExport} variant="outline">Export PDF</Button>
      </div>

      <Tabs defaultValue="devices" className="space-y-4">
        <div className="flex flex-col sm:flex-row gap-4 justify-between items-start sm:items-center">
          <TabsList>
            <TabsTrigger value="devices">Devices</TabsTrigger>
            <TabsTrigger value="versions">Service Versions</TabsTrigger>
          </TabsList>
          <div className="relative w-full sm:w-72">
            <Input 
              placeholder="Search..." 
              value={search} 
              onChange={e => setSearch(e.target.value)} 
              className="bg-secondary/50" 
            />
          </div>
        </div>

        <TabsContent value="devices" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {filteredDevices.map(device => (
              <DeviceCard key={device.id} device={device} />
            ))}
          </div>
          {filteredDevices.length === 0 && (
            <div className="text-center py-12 text-muted-foreground">
              <p>No devices found</p>
            </div>
          )}
        </TabsContent>

         <TabsContent value="versions">
          <div className="rounded-md border border-white/10 bg-black/20 backdrop-blur-sm overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-white/5 border-white/10">
                  <TableHead>IP Address</TableHead>
                  <TableHead>Port</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>Product</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredDevices.flatMap(d => 
                  d.ports.map(p => (
                    <TableRow key={`${d.ip}-${p.number}`} className="hover:bg-white/5 border-white/10">
                      <TableCell className="font-mono text-xs">{d.ip}</TableCell>
                      <TableCell className="font-mono text-xs">{p.number}/{p.protocol}</TableCell>
                      <TableCell className="text-sm font-medium">{p.service || 'unknown'}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{p.product || '-'}</TableCell>
                      <TableCell className="font-mono text-sm text-blue-400">{p.version || '-'}</TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-[200px] truncate">
                        {d.vendor}
                      </TableCell>
                    </TableRow>
                  ))
                )}
                {filteredDevices.flatMap(d => d.ports).length === 0 && (
                   <TableRow>
                     <TableCell colSpan={6} className="text-center h-24 text-muted-foreground">
                       No detected service versions found
                     </TableCell>
                   </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
