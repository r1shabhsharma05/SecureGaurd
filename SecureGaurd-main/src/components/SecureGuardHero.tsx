import SculptureHero from "./ui/liquid-sculpture-hero";
import "./SecureGuardHero.css";

const STATS = [
  { val: "10M+", lbl: "Vulnerabilities Found" },
  { val: "50K+", lbl: "Repos Protected" },
  { val: "99.9%", lbl: "Uptime SLA" },
  { val: "<50ms", lbl: "Avg Scan Time" },
];

/**
 * Landing-page hero: liquid-particle sculpture background (WebGL2, with
 * static-image fallback) + SecureGuard copy, CTAs and the stats strip.
 * The site's own Navbar is rendered separately, so the hero's built-in
 * nav is disabled.
 */
export default function SecureGuardHero() {
  return (
    <>
      <SculptureHero
        showNav={false}
        theme="dark"
        themeToggle={false}
        darkBackground="#000000"
        textColor="#FFFFFF"
        accentColor="#4D7CFE"
        headingFont="'Outfit', 'Geist', 'Helvetica Neue', Arial, sans-serif"
        darkSrc="https://cdn.21st.dev/assets/mirror/a1/a1fa387b6e417b26a25f317559c87cce4d241c1052c52a2b3bc2966b2aaf9b65.webp"
        mobileDarkSrc="https://cdn.21st.dev/assets/mirror/9a/9a82cb59be1bfde59855b79d7a565e487155a89f4d52eac74dcc10e267b2b6d1.webp"
        imageAlt="Abstract metallic sculpture representing SecureGuard's AI security engine"
        eyebrow="AI-Powered Security · Real-Time Scanning"
        headline={"Secure your code\nbefore you ship."}
        headlineAccent="before you ship."
        body="SecureGuard's AI scans every commit for vulnerabilities, exposed secrets and misconfigurations in milliseconds — so you ship fast without shipping risk."
        primaryCta={{ label: "Start Free Trial", href: "/signup" }}
        secondaryCta={{ label: "Watch Demo", href: "#how-it-works" }}
        hint="Move to turn it liquid"
        hintTouch="Touch to turn it liquid"
        backdropText="secureguard"
        showCredit={false}
        intro
        strength={1.15}
        radius={260}
        height="calc(100svh - 76px)"
        style={{ marginTop: 76 }}
      />
      <div className="sg-hero-stats">
        {STATS.map((s) => (
          <div key={s.lbl} className="sg-stat-item">
            <span className="sg-stat-value">{s.val}</span>
            <span className="sg-stat-label">{s.lbl}</span>
          </div>
        ))}
      </div>
    </>
  );
}
