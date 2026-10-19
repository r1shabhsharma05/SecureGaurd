import { BrowserRouter as Router, Routes, Route, useNavigate, useSearchParams } from 'react-router-dom'
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
import { ErrorBoundary } from './components/ErrorBoundary'

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

function App() {
  return (
    <Router>
      <ErrorBoundary>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/signup" element={<AuthPage defaultMode="signup" />} />
          <Route path="/login" element={<AuthPage defaultMode="login" />} />
          <Route path="/onboarding" element={<OnboardingWizard />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/vulnerabilities/:id" element={<VulnerabilityDetailsPage />} />
          <Route path="/accept-invite" element={<InviteRouteHandler />} />
        </Routes>
      </ErrorBoundary>
    </Router>
  )
}

export default App
