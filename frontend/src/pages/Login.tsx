import { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();
  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/';
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    const result = await login({ username, password });
    if (result.success) {
      toast({
        title: 'Access Granted',
        description: 'Welcome to IoT Security Scanner',
      });
      navigate(from, { replace: true });
    } else {
      setError(result.error || 'Authentication failed');
    }
    setIsLoading(false);
  };
  return (
    <div className="min-h-screen bg-background cyber-grid flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-accent/5" />
      <div className="relative w-full max-w-md">
        {}
        <div className="bg-secondary/50 border border-border rounded-t-lg px-4 py-2 flex items-center gap-2">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-destructive/80" />
            <div className="w-3 h-3 rounded-full bg-warning/80" />
            <div className="w-3 h-3 rounded-full bg-accent/80" />
          </div>
          <span className="text-xs text-muted-foreground ml-2 font-mono">
            auth@iot-scanner:~
          </span>
        </div>
        {}
        <div className="bg-card/95 backdrop-blur border-x border-b border-border rounded-b-lg p-8 glow-blue">
          <div className="flex flex-col items-center mb-8">
            <h1 className="text-2xl font-display cyber-heading text-glow-blue text-foreground">
              IoT SCANNER
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Security Authentication Required
            </p>
          </div>
          <form onSubmit={handleSubmit} className="space-y-6">
            {error && (
              <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/30 rounded-md text-destructive text-sm">
                <span>{error}</span>
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="username" className="text-foreground flex items-center gap-2">
                Username
              </Label>
              <Input
                id="username"
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="Enter username"
                className="bg-secondary/50 border-border focus:border-primary font-mono"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password" className="text-foreground flex items-center gap-2">
                Password
              </Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Enter password"
                  className="bg-secondary/50 border-border focus:border-primary font-mono pr-10"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors text-xs font-mono"
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
            </div>
            <Button
              type="submit"
              className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-mono glow-blue"
              disabled={isLoading}
            >
              {isLoading ? (
                <span className="flex items-center gap-2">
                  <div className="w-4 h-4 border-2 border-primary-foreground border-t-transparent rounded-full animate-spin" />
                  Authenticating...
                </span>
              ) : (
                'ACCESS SYSTEM'
              )}
            </Button>
          </form>
          <div className="mt-6 pt-6 border-t border-border">
            <p className="text-xs text-muted-foreground text-center font-mono">
              <span className="text-accent">Demo credentials:</span> admin / admin123
            </p>
          </div>
        </div>
        {}
        <div className="absolute inset-0 pointer-events-none scanline rounded-lg" />
      </div>
    </div>
  );
}