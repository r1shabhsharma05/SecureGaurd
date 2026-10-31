import { useEffect } from 'react';
import { useLocation, useParams } from 'react-router-dom';
import { trackPageView } from '../utils/analytics';

// Day 8 — per-page titles, descriptions, Open Graph tags and canonical URLs.
// This is a client-rendered SPA, so crawlers see the static index.html head;
// PageMeta keeps the live document correct for users, shares and history
// navigation, and records a consent-gated page_view. Private pages
// (dashboard, onboarding, vulnerability detail, invite/reset) are marked
// noindex: they sit behind sign-in and must not appear in search results.
const SITE_URL = 'https://secureguard-main.vercel.app';

type RouteMeta = {
  title: string;
  description: string;
  indexable: boolean;
  crumbs?: Array<{ label: string; path: string }>;
};

const ROUTE_META: Record<string, RouteMeta> = {
  '/': {
    title: 'SecureGuard — AI-Powered Code Security Platform',
    description: 'SecureGuard scans your codebase in real-time with AI to detect vulnerabilities, secrets, and misconfigurations before they reach production.',
    indexable: true,
  },
  '/login': {
    title: 'Log in · SecureGuard',
    description: 'Log in to SecureGuard to review your scan results, vulnerabilities and compliance reports.',
    indexable: true,
    crumbs: [{ label: 'Home', path: '/' }, { label: 'Log in', path: '/login' }],
  },
  '/signup': {
    title: 'Sign up · SecureGuard',
    description: 'Create a free SecureGuard account and run your first AI-powered security scan.',
    indexable: true,
    crumbs: [{ label: 'Home', path: '/' }, { label: 'Sign up', path: '/signup' }],
  },
  '/contact': {
    title: 'Contact us · SecureGuard',
    description: 'Questions about SecureGuard? Send the team a message — we reply by email.',
    indexable: true,
    crumbs: [{ label: 'Home', path: '/' }, { label: 'Contact', path: '/contact' }],
  },
  '/onboarding': {
    title: 'Get started · SecureGuard',
    description: 'Connect a repository, run your first scan and invite your team.',
    indexable: false,
    crumbs: [{ label: 'Home', path: '/' }, { label: 'Onboarding', path: '/onboarding' }],
  },
  '/dashboard': {
    title: 'Dashboard · SecureGuard',
    description: 'Your SecureGuard security overview: repositories, scans, vulnerabilities and compliance reports.',
    indexable: false,
    crumbs: [{ label: 'Home', path: '/' }, { label: 'Dashboard', path: '/dashboard' }],
  },
  '/accept-invite': {
    title: 'Accept invitation · SecureGuard',
    description: 'Accept your SecureGuard organization invitation.',
    indexable: false,
  },
  '/reset-password': {
    title: 'Reset password · SecureGuard',
    description: 'Choose a new password for your SecureGuard account.',
    indexable: false,
  },
};

const NOT_FOUND_META: RouteMeta = {
  title: 'Page not found (404) · SecureGuard',
  description: 'The page you are looking for does not exist. Return to the SecureGuard home page or dashboard.',
  indexable: false,
};

function upsertMeta(attr: 'name' | 'property', key: string, content: string) {
  const selector = `meta[${attr}="${key}"]`;
  let el = document.head.querySelector<HTMLMetaElement>(selector);
  if (!el) {
    el = document.createElement('meta');
    el.setAttribute(attr, key);
    document.head.appendChild(el);
  }
  el.setAttribute('content', content);
}

function upsertCanonical(href: string) {
  let el = document.head.querySelector<HTMLLinkElement>('link[rel="canonical"]');
  if (!el) {
    el = document.createElement('link');
    el.setAttribute('rel', 'canonical');
    document.head.appendChild(el);
  }
  el.setAttribute('href', href);
}

function upsertBreadcrumbJsonLd(crumbs: Array<{ label: string; path: string }>) {
  const id = 'sg-breadcrumb-ld';
  document.getElementById(id)?.remove();
  if (crumbs.length < 2) return;
  const script = document.createElement('script');
  script.id = id;
  script.type = 'application/ld+json';
  script.textContent = JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: crumbs.map((c, i) => ({
      '@type': 'ListItem',
      position: i + 1,
      name: c.label,
      item: `${SITE_URL}${c.path}`,
    })),
  });
  document.head.appendChild(script);
}

export default function PageMeta() {
  const { pathname } = useLocation();
  const params = useParams();

  useEffect(() => {
    let meta: RouteMeta;
    if (pathname.startsWith('/vulnerabilities/')) {
      const id = params.id ?? pathname.split('/').pop();
      meta = {
        title: `Vulnerability ${id} · SecureGuard`,
        description: 'Vulnerability detail: severity, affected file, AI fix, classifier reasoning and occurrence history.',
        indexable: false,
        crumbs: [
          { label: 'Home', path: '/' },
          { label: 'Dashboard', path: '/dashboard' },
          { label: `Vulnerability ${id}`, path: pathname },
        ],
      };
    } else {
      meta = ROUTE_META[pathname] ?? NOT_FOUND_META;
    }

    document.title = meta.title;
    upsertMeta('name', 'description', meta.description);
    upsertMeta('name', 'robots', meta.indexable ? 'index, follow' : 'noindex, nofollow');
    upsertMeta('property', 'og:title', meta.title);
    upsertMeta('property', 'og:description', meta.description);
    upsertMeta('property', 'og:url', `${SITE_URL}${pathname}`);
    upsertMeta('property', 'og:type', 'website');
    upsertCanonical(`${SITE_URL}${pathname}`);
    upsertBreadcrumbJsonLd(meta.crumbs ?? []);

    // New route = top of page. Instant scroll: smooth scrolling on route
    // change disorients keyboard/screen-reader users and fights reduced motion.
    window.scrollTo(0, 0);
    trackPageView(pathname);
  }, [pathname, params.id]);

  return null;
}
