import { useState } from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

const navItems = [
  { path: '/', label: 'Dashboard' },
  { path: '/network', label: 'Network Discovery' },
  { path: '/devices', label: 'Device Inventory' },
  { path: '/vulnerabilities', label: 'Vulnerabilities' },
  { path: '/reports', label: 'Scan Reports' },
  { path: '/logs', label: 'Live Logs' },
  { path: '/settings', label: 'Settings' },
  { path: '/about', label: 'About' },
];

export default function AppLayout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background cyber-grid">
      {/* Top Header */}
      <header className="fixed top-0 left-0 right-0 h-14 bg-card/95 backdrop-blur border-b border-border z-50">
        <div className="flex items-center justify-between h-full px-4">
          <div className="flex items-center gap-4">
            <Button
              variant="ghost"
              size="sm"
              className="md:hidden"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? "Close" : "Menu"}
            </Button>
            
            <Link to="/" className="flex items-center gap-2">
              <span className="font-display cyber-heading text-lg text-glow-blue hidden sm:block">
                IoT SCANNER
              </span>
            </Link>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 bg-secondary/50 rounded border border-border">
              <div className="w-2 h-2 rounded-full status-online animate-pulse" />
              <span className="text-xs text-muted-foreground font-mono">System Online</span>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground hidden sm:block">
                {user?.username}
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={logout}
                className="text-muted-foreground hover:text-destructive"
              >
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed left-0 top-14 bottom-0 bg-sidebar border-r border-sidebar-border transition-all duration-300 z-40',
          sidebarOpen ? 'w-56' : 'w-16',
          mobileMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        )}
      >
        <nav className="flex flex-col h-full p-3">
          <div className="flex-1 space-y-1">
            {navItems.map(item => {
              const isActive = location.pathname === item.path;
              
              const linkContent = (
                <Link
                  to={item.path}
                  onClick={() => setMobileMenuOpen(false)}
                  className={cn(
                    'flex items-center gap-3 px-3 py-2.5 rounded-md transition-all duration-200',
                    isActive
                      ? 'bg-sidebar-primary/10 text-sidebar-primary border border-sidebar-primary/30 glow-blue'
                      : 'text-sidebar-foreground/70 hover:text-sidebar-foreground hover:bg-sidebar-accent'
                  )}
                >
                  {/* No Icon */}
                  {sidebarOpen ? (
                    <span className="font-mono text-sm truncate">{item.label}</span>
                  ) : (
                    <span className="font-mono text-sm font-bold">{item.label.substring(0, 2).toUpperCase()}</span>
                  )}
                </Link>
              );

              if (!sidebarOpen) {
                return (
                  <Tooltip key={item.path} delayDuration={0}>
                    <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
                    <TooltipContent side="right" className="font-mono">
                      {item.label}
                    </TooltipContent>
                  </Tooltip>
                );
              }

              return <div key={item.path}>{linkContent}</div>;
            })}
          </div>

          {/* Collapse Button */}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="hidden md:flex items-center justify-center mt-4 text-muted-foreground hover:text-foreground"
          >
            {sidebarOpen ? (
              <>
                <span className="text-xs font-mono">Collapse</span>
              </>
            ) : (
              <span>&gt;</span>
            )}
          </Button>
        </nav>
      </aside>

      {/* Mobile Overlay */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 bg-background/80 backdrop-blur z-30 md:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Main Content */}
      <main
        className={cn(
          'pt-14 transition-all duration-300',
          sidebarOpen ? 'md:pl-56' : 'md:pl-16'
        )}
      >
        <div className="container mx-auto p-4 md:p-6 lg:p-8 animate-in fade-in zoom-in duration-500">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
