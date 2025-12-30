import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { reportsApi } from '@/services/api';
import type { ScanReport } from '@/types';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';

export default function ScanReports() {
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    reportsApi.getAll().then(res => {
      if (res.success) setReports(res.data!);
      setIsLoading(false);
    });
  }, []);

  const handleDownload = async (id: string) => {
    const blob = await reportsApi.downloadJson(id);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${id}.json`;
    a.click();
    toast({ title: 'Downloaded', description: 'Report saved as JSON' });
  };

  const handlePdfDownload = async (id: string) => {
    try {
        const blob = await reportsApi.downloadPdf(id);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${id.replace('.json', '')}.pdf`;
        a.click();
        toast({ title: 'Downloaded', description: 'Report saved as PDF' });
    } catch (e) {
        toast({ title: 'Error', description: 'Failed to download PDF', variant: 'destructive' });
    }
  };

  const handleDelete = async (report: ScanReport) => {
    if (window.confirm(`Delete report from ${new Date(report.timestamp).toLocaleString()}?`)) {
        setDeletingId(report.id);
        const res = await reportsApi.delete(report.id);
        setDeletingId(null);
        if (res.success) {
            setReports(prev => prev.filter(r => r.id !== report.id));
            toast({ title: 'Report Deleted', description: 'Scan report has been removed.' });
        } else {
            toast({ title: 'Error', description: res.error || 'Failed to delete report', variant: 'destructive' });
        }
    }
  };

  if (isLoading) {
    return <div className="flex items-center justify-center h-64"><div className="w-12 h-12 border-2 border-primary border-t-transparent rounded-full animate-spin" /></div>;
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display cyber-heading text-glow-blue">Scan Reports</h1>
          <p className="text-muted-foreground text-sm">{reports.length} reports available</p>
        </div>
        <Link to="/">
            <Button className="glow-blue">
                Start New Scan
            </Button>
        </Link>
      </div>

      <div className="space-y-4">
        {reports.map(report => (
          <div key={report.id} className="cyber-card p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                {/* Icon Removed */}
                <div>
                  <p className="font-mono text-sm">{report.mode.toUpperCase()} Scan</p>
                  <p className="text-xs text-muted-foreground flex items-center gap-1">
                    {new Date(report.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="text-right text-sm mr-4 hidden md:block">
                  <p><span className="text-muted-foreground">Devices:</span> {report.summary.totalDevices}</p>
                  <p><span className="text-muted-foreground">Vulnerabilities:</span> <span className="text-destructive">{report.summary.totalVulnerabilities}</span></p>
                </div>
                <Button variant="outline" size="sm" onClick={() => handleDownload(report.id)}>
                  JSON
                </Button>
                <Button variant="outline" size="sm" onClick={() => handlePdfDownload(report.id)}>
                  PDF
                </Button>
                <Button 
                  variant="destructive" 
                  size="sm" 
                  onClick={() => handleDelete(report)}
                  disabled={deletingId === report.id}
                >
                  {deletingId === report.id ? (
                    <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                  ) : (
                    "Delete"
                  )}
                </Button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
