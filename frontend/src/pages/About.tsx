export default function About() {
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="text-center py-12">
        <h1 className="text-3xl font-display cyber-heading text-glow-blue mb-2">IoT Security Scanner</h1>
        <p className="text-muted-foreground">Version 1.0.0</p>
      </div>
      <div className="max-w-2xl mx-auto cyber-card p-6">
        <h2 className="text-lg font-display mb-4">About</h2>
        <p className="text-sm text-muted-foreground mb-4">
          A comprehensive IoT network security scanner designed to discover devices, identify vulnerabilities, 
          and provide actionable remediation guidance. Built with modern web technologies and AI-powered analysis.
        </p>
        <h3 className="font-display text-sm mb-2 mt-6">Features</h3>
        <ul className="text-sm text-muted-foreground space-y-1">
          <li> Network device discovery and fingerprinting</li>
          <li> CVE vulnerability detection and analysis</li>
          <li> Real-time scan monitoring and logging</li>
          <li> Comprehensive reporting and export</li>
          <li> AI-powered threat assessment</li>
        </ul>
        <div className="flex gap-4 mt-6 pt-6 border-t border-border">
          <a href="#" className="flex items-center gap-2 text-sm text-primary hover:underline">GitHub</a>
          <a href="#" className="flex items-center gap-2 text-sm text-primary hover:underline">Documentation</a>
          <a href="#" className="flex items-center gap-2 text-sm text-primary hover:underline">API Reference</a>
        </div>
      </div>
    </div>
  );
}