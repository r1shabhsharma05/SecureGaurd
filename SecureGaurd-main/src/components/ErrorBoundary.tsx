import { Component, type ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
}

/**
 * Catches render-time crashes anywhere in the subtree and shows a
 * recoverable fallback instead of a blank page. Wrap route content
 * with this so one broken page can't take down the whole app.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: unknown, info: unknown): void {
    // eslint-disable-next-line no-console
    console.error('Unhandled UI error caught by ErrorBoundary:', error, info);
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
        </div>
      );
    }
    return this.props.children;
  }
}
