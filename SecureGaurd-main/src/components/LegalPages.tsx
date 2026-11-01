import { Link } from 'react-router-dom';
import type { ReactNode } from 'react';
import Breadcrumbs from './Breadcrumbs';
import './Legal.css';

// Day 9 — Privacy Policy and Terms of Service. The content describes what
// the product actually does today: no certifications are claimed (the
// product generates compliance reports; it does not hold SOC 2 / ISO
// certifications), processors are the services actually in use, and
// deletion is the real Settings → Delete account flow. If a processor
// or behavior changes, this page must change with it.
function LegalPage({ title, intro, children }: { title: string; intro: string; children: ReactNode }) {
  return (
    <main className="legal-page">
      <div className="container">
        <Breadcrumbs items={[{ label: 'Home', to: '/' }, { label: title }]} />
        <h1>{title}</h1>
        <p className="legal-updated">Last updated: 1 November 2026</p>
        <p className="legal-intro">{intro}</p>
        {children}
        <p className="legal-contact">
          Questions about this page? <Link to="/contact">Contact us</Link> and we will reply by email.
        </p>
      </div>
    </main>
  );
}

export function PrivacyPolicy() {
  return (
    <LegalPage
      title="Privacy Policy"
      intro="SecureGuard is an AI-powered code security platform. This policy explains what data we collect, why we collect it, and the choices you have. We collect only what the service needs to scan code, show results, and keep accounts secure."
    >
      <section>
        <h2>1. Data we collect</h2>
        <ul>
          <li><strong>Account data:</strong> your name, email address, and a hashed password. We never store passwords in readable form.</li>
          <li><strong>Repository data:</strong> the repositories you connect (name, URL, platform) and the findings of each scan — file paths, severity, rule identifiers, and short code snippets around a finding. We do not retain full copies of your codebase.</li>
          <li><strong>Access tokens:</strong> GitHub/GitLab personal access tokens you provide are encrypted at rest and used only to fetch code and post scan results where you configured it.</li>
          <li><strong>Product analytics:</strong> only if you accept analytics cookies — page views and product events (signups, scans started, fixes applied) with a random per-tab session id. We do not record IP addresses in analytics and never accept email or name fields in analytics events.</li>
          <li><strong>Contact messages:</strong> the name, email, and message you send through the contact form, kept so we can reply.</li>
          <li><strong>Security data:</strong> audit logs of privileged actions (member changes, billing changes) inside your organization, kept for accountability.</li>
        </ul>
      </section>
      <section>
        <h2>2. How we use it</h2>
        <p>
          To run scans and show you results, manage your account and organizations, send verification,
          password-reset, and invitation emails, operate billing, and improve the product in aggregate.
          We do not sell personal data, and we do not use your code to train models for other customers.
        </p>
      </section>
      <section>
        <h2>3. Service providers (processors)</h2>
        <p>Your data is processed by the following services, only as needed to run SecureGuard:</p>
        <ul>
          <li><strong>Render</strong> — backend hosting. <strong>Vercel</strong> — frontend hosting.</li>
          <li><strong>Supabase (PostgreSQL)</strong> — the application database.</li>
          <li><strong>Brevo</strong> — transactional email (verification, resets, invitations, contact replies).</li>
          <li><strong>Razorpay</strong> — subscription billing (INR). Payment details go directly to Razorpay; we store only plan and subscription status.</li>
          <li><strong>Cloudflare Turnstile</strong> — bot protection on public forms, only once activated.</li>
          <li><strong>Sentry</strong> — error tracking, only once activated; error reports contain no passwords or access tokens.</li>
        </ul>
      </section>
      <section>
        <h2>4. Cookies</h2>
        <p>
          A secure, HTTP-only cookie keeps you signed in (refresh token). A local-storage choice stores
          your cookie-consent decision. Analytics cookies load only after you accept them in the consent
          banner, and you can change your choice any time from “Cookie Settings” in the footer. Refusing
          analytics does not limit the product.
        </p>
      </section>
      <section>
        <h2>5. Data retention and deletion</h2>
        <p>
          Account and scan data is kept while your account is active. You can delete your account at any
          time from Dashboard → Settings → Delete account (password + typed confirmation required). Deletion
          removes your account, personal repositories, and scans; organizations you solely own are handed to
          another member or deleted if you are the only member. Backups, where enabled, may retain deleted
          data for a limited period before rotating out.
        </p>
      </section>
      <section>
        <h2>6. Security</h2>
        <p>
          Passwords are hashed, tokens are encrypted at rest, traffic is HTTPS-only, and organization data
          is isolated per organization at the API layer. No system is perfectly secure; if you believe you
          found a security issue, contact us through the contact form.
        </p>
      </section>
      <section>
        <h2>7. Your rights</h2>
        <p>
          You can view and manage your account data in the dashboard, correct your profile details, export
          your reports, and delete your account as described above. For any other request about your data,
          contact us and we will respond by email.
        </p>
      </section>
      <section>
        <h2>8. Changes</h2>
        <p>
          If this policy changes in a way that affects how your data is used, the “Last updated” date above
          changes and the new version applies from publication.
        </p>
      </section>
    </LegalPage>
  );
}

export function TermsOfService() {
  return (
    <LegalPage
      title="Terms of Service"
      intro="These terms govern your use of SecureGuard. By creating an account you agree to them. If you do not agree, do not use the service."
    >
      <section>
        <h2>1. The service</h2>
        <p>
          SecureGuard scans code repositories you connect for vulnerabilities, exposed secrets, dependency
          risks, and infrastructure misconfigurations, and produces findings, AI-suggested fixes, SBOMs,
          and compliance reports. Results are advisory: a scan finding is a signal to review, not proof
          that code is exploitable, and the absence of findings is not proof that code is secure.
        </p>
      </section>
      <section>
        <h2>2. Accounts and organizations</h2>
        <p>
          You are responsible for keeping your credentials safe and for activity under your account.
          Organizations have roles (Owner, Admin, Developer, Auditor); Owners and Admins manage members
          and billing. You must only connect repositories you have the right to scan.
        </p>
      </section>
      <section>
        <h2>3. Acceptable use</h2>
        <ul>
          <li>Do not scan code you have no right to access, and do not use the service to attack, probe, or disrupt other systems.</li>
          <li>Do not attempt to access another organization&apos;s data, bypass access controls, or abuse rate limits and public forms.</li>
          <li>Do not upload credentials belonging to others as your own access tokens.</li>
        </ul>
        <p>We may suspend accounts that violate these terms or threaten the security of the service.</p>
      </section>
      <section>
        <h2>4. Plans and billing</h2>
        <p>
          A free plan is available with the limits shown on the pricing page. Paid plans (Pro, Enterprise)
          are billed in INR through Razorpay; subscriptions renew until cancelled, cancellation takes
          effect at the end of the current billing period, and plan limits follow the active subscription.
          Prices shown on the pricing page apply; taxes, where applicable, follow Razorpay&apos;s checkout.
        </p>
      </section>
      <section>
        <h2>5. Compliance reports</h2>
        <p>
          SecureGuard generates compliance reports (SOC 2, HIPAA, PCI DSS, GDPR mappings) from your scan
          findings. These reports are working documents to support your own compliance work. SecureGuard
          itself is not SOC 2 or ISO 27001 certified, and a generated report is not a certification.
        </p>
      </section>
      <section>
        <h2>6. Availability and liability</h2>
        <p>
          We aim to keep the service available but do not guarantee uninterrupted operation; scheduled
          maintenance and third-party outages may interrupt it. To the extent permitted by law, the service
          is provided “as is”, and our liability for any claim related to the service is limited to the
          fees you paid in the 12 months before the claim. Nothing in these terms limits liability that
          cannot be limited by law.
        </p>
      </section>
      <section>
        <h2>7. Termination</h2>
        <p>
          You may delete your account at any time from Settings. We may suspend or terminate accounts that
          breach these terms. On termination, your access ends and your data is handled as described in
          the Privacy Policy.
        </p>
      </section>
      <section>
        <h2>8. Changes to these terms</h2>
        <p>
          We may update these terms as the service evolves. Material changes will be reflected in the
          “Last updated” date above, and continued use after publication means you accept the updated terms.
        </p>
      </section>
    </LegalPage>
  );
}
