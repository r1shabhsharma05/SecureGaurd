import { Link } from 'react-router-dom';
import './Breadcrumbs.css';

export type Crumb = { label: string; to?: string };

// Day 8 — breadcrumb navigation. The last crumb is the current page
// (plain text, aria-current); earlier crumbs are links.
export default function Breadcrumbs({ items }: { items: Crumb[] }) {
  if (items.length === 0) return null;
  return (
    <nav className="breadcrumbs" aria-label="Breadcrumb">
      <ol className="breadcrumbs-list">
        {items.map((item, i) => {
          const isLast = i === items.length - 1;
          return (
            <li key={`${item.label}-${i}`} className="breadcrumbs-item">
              {isLast || !item.to ? (
                <span aria-current={isLast ? 'page' : undefined}>{item.label}</span>
              ) : (
                <Link to={item.to}>{item.label}</Link>
              )}
              {!isLast && <span className="breadcrumbs-separator" aria-hidden="true">/</span>}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
