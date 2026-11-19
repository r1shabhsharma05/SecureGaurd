import { Component, type ReactNode } from 'react';
import * as Sentry from '@sentry/react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  // TEMPORARY diagnostic (19 Nov 2026): the dashboard crashes on every
  // load and the browser session cannot open DevTools, so the fallback
  // renders the error itself until the root cause is fixed — then this
  // goes back to the generic message. Never ship error text to users.
  errorMessage?: string;
  componentStack?: string;
}

/**
 * Catches render-time crashes anywhere in the subtree and shows a
 * recoverable fallback instead of a blank page. Wrap route content
 * with this so one broken page can't take down the whole app.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(error: unknown): ErrorBoundaryState {
    return {
      hasError: true,
      errorMessage: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    };
  }

  componentDidCatch(error: unknown, info: unknown): void {
    console.error('Unhandled UI error caught by ErrorBoundary:', error, info);
    this.setState({
      componentStack: (info as { componentStack?: string })?.componentStack,
    });
    // Day 9: Sentry capture when a DSN is configured; a no-op otherwise.
    try {
      Sentry.captureException(error, {
        extra: { componentStack: (info as { componentStack?: string })?.componentStack },
      });
    } catch {
      // Tracking must never break the fallback UI.
    }
  }

  private handleReload = (): void => {
    window.location.reload();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div
          style={{
            minHeight: '60vh',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '1rem',
            padding: '2rem',
            textAlign: 'center',
            color: 'var(--text-main, #e8eaf0)',
          }}
          role="alert"
        >
          <h2 style={{ margin: 0 }}>Something went wrong</h2>
          <p style={{ margin: 0, color: 'var(--text-dim, #9aa0b4)', maxWidth: '28rem' }}>
            An unexpected error interrupted this page. Your data is safe —
            reloading usually resolves it.
          </p>
          <button
            type="button"
            onClick={this.handleReload}
            className="connect-repo-btn"
            style={{ padding: '0.6rem 1.4rem', cursor: 'pointer' }}
          >
            Reload page
          </button>
          {/* TEMPORARY diagnostic — see state comment above. */}
          {this.state.errorMessage && (
            <details open style={{ maxWidth: '44rem', textAlign: 'left', fontSize: '0.8rem' }}>
              <summary>Error details (temporary diagnostic)</summary>
              <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{this.state.errorMessage}</pre>
              {this.state.componentStack && (
                <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{this.state.componentStack}</pre>
              )}
            </details>
          )}
        </div>
      );
    }
    return this.props.children;
  }
}
