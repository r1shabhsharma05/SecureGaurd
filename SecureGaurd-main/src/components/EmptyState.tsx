import { Link } from 'react-router-dom';
import type { ReactNode } from 'react';
import './EmptyState.css';

// Day 8 — shared empty state: every list that can legitimately be empty
// explains why and offers the next action, instead of rendering blank.
export default function EmptyState({
  icon,
  title,
  body,
  actionLabel,
  actionTo,
  onAction,
}: {
  icon?: ReactNode;
  title: string;
  body?: string;
  actionLabel?: string;
  actionTo?: string;
  onAction?: () => void;
}) {
  return (
    <div className="empty-state">
      {icon && <div className="empty-state-icon">{icon}</div>}
      <h3 className="empty-state-title">{title}</h3>
      {body && <p className="empty-state-body">{body}</p>}
      {actionLabel && actionTo && (
        <Link className="empty-state-action" to={actionTo}>{actionLabel}</Link>
      )}
      {actionLabel && !actionTo && onAction && (
        <button type="button" className="empty-state-action" onClick={onAction}>{actionLabel}</button>
      )}
    </div>
  );
}
