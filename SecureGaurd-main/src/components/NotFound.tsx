import { Link } from 'react-router-dom';
import Breadcrumbs from './Breadcrumbs';
import './NotFound.css';

// Day 8 — custom 404 page. The SPA fallback serves index.html for unknown
// paths, so this catch-all route is the 404 surface: it says plainly that
// the page does not exist and links to the real destinations instead of
// leaving a blank shell.
export default function NotFound() {
  return (
    <main className="not-found">
      <div className="container">
        <Breadcrumbs items={[{ label: 'Home', to: '/' }, { label: 'Page not found' }]} />
        <p className="not-found-code" aria-hidden="true">404</p>
        <h1>Page not found</h1>
        <p className="not-found-body">
          The page you are looking for does not exist or was moved. Check the address,
          or head to one of these instead.
        </p>
        <div className="not-found-actions">
          <Link className="not-found-action not-found-action--primary" to="/">Go to home page</Link>
          <Link className="not-found-action" to="/dashboard">Open dashboard</Link>
          <Link className="not-found-action" to="/contact">Contact us</Link>
        </div>
      </div>
    </main>
  );
}
