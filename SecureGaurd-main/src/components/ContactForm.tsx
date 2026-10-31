import { useState } from 'react';
import type { FormEvent } from 'react';
import { apiUrl } from '../config/api';
import { trackEvent } from '../utils/analytics';
import { useToast } from './Toast';
import './ContactForm.css';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// Day 8 — contact form. Submits to POST /api/contact, which emails the team
// inbox via Brevo and stores the message only after the provider accepts
// it. Success is shown only on a 200/201 response; failures show the
// server's honest message. The hidden "company" field is a honeypot: bots
// fill it, humans never see it.
export default function ContactForm() {
  const { pushToast } = useToast();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [company, setCompany] = useState('');
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    if (name.trim().length < 2 || name.trim().length > 100) {
      setError('Name must be 2–100 characters.');
      return;
    }
    if (!EMAIL_RE.test(email.trim())) {
      setError('A valid email address is required so we can reply.');
      return;
    }
    if (subject.trim().length > 140) {
      setError('Subject must be at most 140 characters.');
      return;
    }
    if (message.trim().length < 10 || message.trim().length > 2000) {
      setError('Message must be 10–2000 characters.');
      return;
    }
    setSending(true);
    try {
      const res = await fetch(apiUrl('/api/contact'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), email: email.trim(), subject: subject.trim(), message: message.trim(), company }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.message || 'Your message could not be sent. Please try again later.');
        return;
      }
      setSent(true);
      trackEvent('contact_sent');
      pushToast('success', 'Thanks — your message has been received.');
    } catch {
      setError('Your message could not be sent. Check your connection and try again.');
    } finally {
      setSending(false);
    }
  }

  if (sent) {
    return (
      <div className="contact-sent" role="status">
        <h2>Message sent</h2>
        <p>Thanks for reaching out — the SecureGuard team will reply to {email.trim()} by email.</p>
      </div>
    );
  }

  return (
    <form className="contact-form" onSubmit={handleSubmit} noValidate>
      {error && <p className="contact-error" role="alert">{error}</p>}
      <label className="contact-field">
        <span>Name</span>
        <input type="text" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" required />
      </label>
      <label className="contact-field">
        <span>Email</span>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required />
      </label>
      <label className="contact-field">
        <span>Subject (optional)</span>
        <input type="text" value={subject} onChange={(e) => setSubject(e.target.value)} maxLength={140} />
      </label>
      <label className="contact-field">
        <span>Message</span>
        <textarea value={message} onChange={(e) => setMessage(e.target.value)} rows={6} maxLength={2000} required />
      </label>
      {/* Honeypot: hidden from humans, filled by bots. */}
      <label className="contact-honeypot" aria-hidden="true" tabIndex={-1}>
        <span>Company</span>
        <input type="text" value={company} onChange={(e) => setCompany(e.target.value)} tabIndex={-1} autoComplete="off" />
      </label>
      <button type="submit" className="contact-submit" disabled={sending}>
        {sending ? 'Sending…' : 'Send message'}
      </button>
      <p className="contact-note">Messages go to the SecureGuard team inbox and are answered by email.</p>
    </form>
  );
}
