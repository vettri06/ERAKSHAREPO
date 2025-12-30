import React, { Component, ErrorInfo, ReactNode } from 'react';
import { Button } from '@/components/ui/button';

interface Props {
  children?: ReactNode;
}
interface State {
  hasError: boolean;
  error: Error | null;
}
export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };
  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }
  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }
  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4">
          <div className="bg-card border border-destructive/50 rounded-lg p-6 max-w-md w-full shadow-lg">
            <div className="flex items-center gap-3 mb-4 text-destructive">
              <h1 className="text-xl font-bold">Something went wrong</h1>
            </div>
            <p className="text-muted-foreground mb-4">
              An error occurred while rendering the application.
            </p>
            <div className="bg-secondary/50 p-4 rounded-md mb-6 overflow-auto max-h-40">
              <code className="text-xs text-destructive font-mono">
                {this.state.error?.message}
              </code>
            </div>
            <Button 
              onClick={() => window.location.href = '/'} 
              className="w-full"
            >
              Return to Home
            </Button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}