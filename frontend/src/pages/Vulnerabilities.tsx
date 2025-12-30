import { useEffect, useState } from 'react';
import { vulnerabilitiesApi } from '@/services/api';
import type { Vulnerability, Severity } from '@/types';
import { SeverityBadge } from '@/components/SeverityBadge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export default function Vulnerabilities() {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [filter, setFilter] = useState<Severity | 'all'>('all');
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'vulnerability' | 'misconfiguration' | 'exposure'>('all');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchVulnerabilities = () => {
      vulnerabilitiesApi.getAll().then(res => {
        if (res.success && res.data) setVulnerabilities(res.data);
        setIsLoading(false);
      });
    };

    fetchVulnerabilities();
    const interval = setInterval(fetchVulnerabilities, 5000);
    return () => clearInterval(interval);
  }, []);

  const filtered = vulnerabilities.filter(v => {
    const matchesSeverity = filter === 'all' ? true : v.severity === filter;
    const matchesCategory = categoryFilter === 'all' ? true : v.category === categoryFilter;
    return matchesSeverity && matchesCategory;
  });

  if (isLoading) {
    return <div className="flex items-center justify-center h-64"><div className="w-12 h-12 border-2 border-primary border-t-transparent rounded-full animate-spin" /></div>;
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-display cyber-heading text-glow-blue">Vulnerability Analysis</h1>
        <p className="text-muted-foreground text-sm">{vulnerabilities.length} findings detected across the network</p>
      </div>

      <div className="bg-secondary/30 border border-primary/20 rounded-lg p-3 flex items-start gap-3">
        {/* Icon Removed */}
        <p className="text-sm text-muted-foreground">
          Findings are based on passive service detection and public CVE data; manual validation is recommended.
        </p>
      </div>

      <div className="flex flex-col sm:flex-row gap-4 justify-between">
        <div className="flex gap-2 overflow-x-auto pb-2 sm:pb-0">
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map(sev => (
            <Button 
              key={sev} 
              variant={filter === sev ? 'default' : 'outline'} 
              size="sm" 
              onClick={() => setFilter(sev)} 
              className={cn(filter === sev && 'glow-blue')}
            >
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
            </Button>
          ))}
        </div>
        <div className="flex gap-2 overflow-x-auto pb-2 sm:pb-0">
          {(['all', 'vulnerability', 'misconfiguration', 'exposure'] as const).map(cat => (
             <Button 
             key={cat} 
             variant={categoryFilter === cat ? 'secondary' : 'ghost'} 
             size="sm" 
             onClick={() => setCategoryFilter(cat)}
             className={cn("border border-transparent", categoryFilter === cat && "border-primary/30 bg-primary/10")}
           >
             {cat.charAt(0).toUpperCase() + cat.slice(1)}
           </Button>
          ))}
        </div>
      </div>

      <div className="space-y-4">
        {filtered.map(vuln => (
          <div key={vuln.id} className="cyber-card p-4">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2 flex-wrap">
                  <SeverityBadge severity={vuln.severity} />
                  {vuln.category && (
                    <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-secondary text-xs font-medium border border-white/5">
                      {/* Icon Removed */}
                      <span className="capitalize">{vuln.category}</span>
                    </div>
                  )}
                  <span className="font-mono text-primary">{vuln.cve_id}</span>
                  {new Date(vuln.published_date).getFullYear() < 2012 && (
                    <span className="text-xs px-2 py-0.5 rounded bg-muted text-muted-foreground border border-border">
                      Legacy CVE
                    </span>
                  )}
                  {vuln.cvss_score > 0 && (
                    <span className="text-xs text-muted-foreground">CVSS: {vuln.cvss_score}</span>
                  )}
                  {vuln.confidence && (
                    <span className={cn(
                      "text-xs px-2 py-0.5 rounded border",
                      vuln.confidence === 'HIGH' ? "bg-green-500/10 text-green-400 border-green-500/30" :
                      vuln.confidence === 'MEDIUM' ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30" :
                      "bg-blue-500/10 text-blue-400 border-blue-500/30"
                    )}>
                      {vuln.confidence} Confidence
                    </span>
                  )}
                  {vuln.status === 'potential' && (
                    <span className="text-xs px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/30">
                      Potential
                    </span>
                  )}
                </div>
                <p className="text-sm text-foreground mb-3">{vuln.description}</p>
                <div className="bg-secondary/20 p-3 rounded border border-white/5">
                  <p className="text-xs text-muted-foreground mb-1 font-semibold uppercase tracking-wider">Current Version</p>
                  <p className="text-sm text-foreground/90 font-mono">{vuln.version_checked || "Unknown"}</p>
                  {vuln.download_link && (
                    <div className="mt-3">
                      <Button size="sm" variant="outline" className="h-8 gap-2" onClick={() => window.open(vuln.download_link, '_blank')}>
                        Download Update
                      </Button>
                    </div>
                  )}
                </div>
                <div className="mt-3 flex items-center gap-4 text-xs text-muted-foreground">
                  <span>Affected: <span className="text-foreground font-mono">{vuln.affected_devices.join(', ')}</span></span>
                  {vuln.published_date && <span>Published: {new Date(vuln.published_date).toLocaleDateString()}</span>}
                </div>
              </div>
              {vuln.references && vuln.references.length > 0 && (
                <a href={vuln.references[0]} target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80 p-1 hover:bg-primary/10 rounded transition-colors text-xs font-mono border border-primary/20">
                  Ref
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
      {filtered.length === 0 && (
        <div className="text-center py-12 text-muted-foreground">
          <p>No findings match your filters</p>
        </div>
      )}
    </div>
  );
}
