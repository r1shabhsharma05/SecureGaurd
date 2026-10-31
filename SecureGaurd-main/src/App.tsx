import { BrowserRouter as Router, Routes, Route, useNavigate, useSearchParams } from 'react-router-dom'
import { MotionConfig } from 'framer-motion'
import './index.css'
import Navbar from './components/Navbar'
import Hero from './components/Hero'
import Features from './components/Features'
import HowItWorks from './components/HowItWorks'
import Pricing from './components/Pricing'
import CTA from './components/CTA'
import Footer from './components/Footer'
import AuthPage from './components/AuthPage'
import Dashboard from './components/Dashboard'
import OnboardingWizard from './components/OnboardingWizard'
import VulnerabilityDetailsPage from './components/VulnerabilityDetailsPage'
import { AcceptInvitePage } from './components/AcceptInvitePage'
import { ResetPasswordPage } from './components/ResetPasswordPage'
import { ErrorBoundary } from './components/ErrorBoundary'
import { ToastProvider } from './components/Toast'
import { ConsentProvider } from './components/CookieConsent'
import PageMeta from './components/PageMeta'
import Breadcrumbs from './components/Breadcrumbs'
import ContactForm from './components/ContactForm'
import NotFound from './components/NotFound'

function Home() {
  return (
    <>
      <Navbar />
      <main>
        <Hero />
        <Features />
        <HowItWorks />
        <Pricing />
        <CTA />
      </main>
      <Footer />
    </>
  )
}

function ContactPage() {
  return (
    <>
      <Navbar />
      <main className="contact-page">
        <div className="container">
          <Breadcrumbs items={[{ label: 'Home', to: '/' }, { label: 'Contact' }]} />
          <h1>Contact us</h1>
          <p className="contact-page-intro">
            Questions about SecureGuard, pricing, or a security review? Send us a message
            and the team will reply by email. New to SecureGuard?{' '}
            <a href="/signup">Create a free account</a> or read{' '}
            <a href="/#features">how it works</a> first.
          </p>
          <ContactForm />
        </div>
      </main>
      <Footer />
    </>
  )
}

function InviteRouteHandler() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get('token') || '';

  return (
    <AcceptInvitePage
      token={token}
      onAccepted={() => navigate('/dashboard')}
      onNavigateAuth={() => navigate(`/login?redirect=${encodeURIComponent(`/accept-invite?token=${token}`)}`)}
    />
  );
}

function ResetPasswordRouteHandler() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token') || '';

  return <ResetPasswordPage token={token} />;
}

function App() {
  return (
    <ToastProvider>
      <ConsentProvider>
        <Router>
          {/* Day 8: all framer-motion animations respect the OS
              reduced-motion setting; GSAP entrances check it directly. */}
          <MotionConfig reducedMotion="user">
            <ErrorBoundary>
              <PageMeta />
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/signup" element={<AuthPage defaultMode="signup" />} />
                <Route path="/login" element={<AuthPage defaultMode="login" />} />
                <Route path="/contact" element={<ContactPage />} />
                <Route path="/onboarding" element={<OnboardingWizard />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/vulnerabilities/:id" element={<VulnerabilityDetailsPage />} />
                <Route path="/accept-invite" element={<InviteRouteHandler />} />
                <Route path="/reset-password" element={<ResetPasswordRouteHandler />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </ErrorBoundary>
          </MotionConfig>
        </Router>
      </ConsentProvider>
    </ToastProvider>
  )
}

export default App
