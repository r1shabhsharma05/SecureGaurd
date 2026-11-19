import React from 'react';

// In-page confirmation for destructive actions. Native window.confirm is
// auto-dismissed by automated browsers and froze tabs in testing, which
// made Disconnect/Revoke look dead — same reason the scan-start confirm
// moved in-page. Inline styles keep it usable from any component without
// depending on that component's stylesheet.
interface ConfirmModalProps {
  title: string;
  body: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmModal({ title, body, confirmLabel, onConfirm, onCancel }: ConfirmModalProps) {
  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.7)',
        backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center',
        justifyContent: 'center', zIndex: 3000,
      }}
      onClick={onCancel}
    >
      <div
        style={{
          width: '100%', maxWidth: '420px', background: '#0f172a',
          border: '1px solid #1e293b', borderRadius: '12px',
          padding: '1.5rem', margin: '1rem',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 style={{ margin: '0 0 0.75rem 0', color: '#f8fafc', fontSize: '1.1rem' }}>{title}</h3>
        <p style={{ margin: '0 0 1.25rem 0', color: '#cbd5e1', fontSize: '0.9rem', lineHeight: 1.5 }}>{body}</p>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
          <button
            type="button"
            onClick={onCancel}
            style={{
              background: '#1e293b', border: '1px solid #334155', color: '#f8fafc',
              padding: '0.55rem 1.1rem', borderRadius: '8px', cursor: 'pointer', fontWeight: 600,
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            style={{
              background: '#dc2626', border: 'none', color: '#ffffff',
              padding: '0.55rem 1.1rem', borderRadius: '8px', cursor: 'pointer', fontWeight: 600,
            }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
