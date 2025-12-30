import { useState } from 'react';
import { authApi, settingsApi } from '@/services/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
export default function Settings() {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();
  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    const res = await authApi.changePassword(oldPassword, newPassword);
    if (res.success) {
      toast({ title: 'Success', description: 'Password changed successfully' });
      setOldPassword('');
      setNewPassword('');
    } else {
      toast({ title: 'Error', description: res.error, variant: 'destructive' });
    }
    setIsLoading(false);
  };
  const handleExport = async () => {
    const blob = await settingsApi.exportConfig();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'config.json';
    a.click();
    toast({ title: 'Exported', description: 'Configuration exported' });
  };
  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-display cyber-heading text-glow-blue flex items-center gap-2">
          Settings
        </h1>
        <p className="text-muted-foreground text-sm">Configure scanner settings</p>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="cyber-card p-6">
          <h2 className="text-lg font-display mb-4 flex items-center gap-2">Change Password</h2>
          <form onSubmit={handlePasswordChange} className="space-y-4">
            <div><Label>Current Password</Label><Input type="password" value={oldPassword} onChange={e => setOldPassword(e.target.value)} className="bg-secondary/50" /></div>
            <div><Label>New Password</Label><Input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} className="bg-secondary/50" /></div>
            <Button type="submit" disabled={isLoading}>Save</Button>
          </form>
        </div>
        <div className="cyber-card p-6">
          <h2 className="text-lg font-display mb-4">Configuration</h2>
          <div className="space-y-4">
            <Button variant="outline" onClick={handleExport} className="w-full justify-start">Export Configuration</Button>
            <Button variant="outline" className="w-full justify-start">Import Configuration</Button>
          </div>
          <div className="mt-6 p-3 bg-accent/10 border border-accent/30 rounded">
            <p className="text-sm"><span className="text-accent font-bold">AI Model:</span> Online</p>
          </div>
        </div>
      </div>
    </div>
  );
}