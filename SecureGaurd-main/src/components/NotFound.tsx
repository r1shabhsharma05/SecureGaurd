import { Link } from 'react-router-dom';
import './NotFound.css';

// Custom 404 page — the user's CodePen design ("Look like you're lost").
// Ported to React: same white page, Arvo font, the Dribbble 404 GIF
// (self-hosted at /404.gif so the page never depends on a hotlinked CDN),
// same green "Go to Home" button. No Bootstrap — the centered column is
// plain flexbox in NotFound.css. One fix vs the original: "avaible" →
// "available". The SPA fallback serves index.html for unknown paths, so
// this catch-all route is the 404 surface.
export default function NotFound() {
  return (
    <main className="page_404">
      <div className="page_404-container">
        <div className="four_zero_four_bg">
          <h1 className="text-center">404</h1>
        </div>

        <div className="contant_box_404">
          <h3 className="h2">
            Look like you&apos;re lost
          </h3>

          <p>the page you are looking for not available!</p>

          <Link to="/" className="link_404">Go to Home</Link>
        </div>
      </div>
    </main>
  );
}
