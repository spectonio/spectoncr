import { Link, NavLink } from 'react-router-dom';
import { ReactNode, useEffect, useState } from 'react';

// Shared chrome for both routes: the steel header (the app's signature,
// steel in both themes), a persisted light/dark toggle, and a few small
// primitives so App and ScanDetail stay declarative.

type Theme = 'light' | 'dark';
const THEME_KEY = 'specton-theme';

/** Read the persisted theme, apply it to <html data-theme>, expose a toggle. */
export function useTheme(): [Theme | null, () => void] {
  const [theme, setTheme] = useState<Theme | null>(null);

  useEffect(() => {
    const saved = (localStorage.getItem(THEME_KEY) as Theme | null) ?? null;
    setTheme(saved);
    if (saved) document.documentElement.setAttribute('data-theme', saved);
  }, []);

  function toggle() {
    const sysDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const current = theme ?? (sysDark ? 'dark' : 'light');
    const next: Theme = current === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem(THEME_KEY, next);
    document.documentElement.setAttribute('data-theme', next);
  }

  return [theme, toggle];
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function SunMoon({ dark }: { dark: boolean }) {
  return dark ? (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
    </svg>
  ) : (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </svg>
  );
}

/** The steel header. `right` renders inside the bar (e.g. the API-key control). */
export function Header({ right }: { right?: ReactNode }) {
  const [theme, toggle] = useTheme();
  const isDark =
    theme === 'dark' ||
    (theme === null && typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches);

  const nav = (
    <nav className="header-nav" aria-label="Primary">
      <NavLink to="/browse" className={({ isActive }) => (isActive ? 'active' : undefined)}>
        Browse
      </NavLink>
      <NavLink to="/audit" className={({ isActive }) => (isActive ? 'active' : undefined)}>
        Audit
      </NavLink>
      <NavLink to="/policies" className={({ isActive }) => (isActive ? 'active' : undefined)}>
        Policies
      </NavLink>
      <NavLink to="/" end className={({ isActive }) => (isActive ? 'active' : undefined)}>
        CVE Search
      </NavLink>
    </nav>
  );

  return (
    <header className="header">
      <div className="header-inner">
        <Link to="/browse" className="brand" aria-label="SpectonCR home">
          <span className="brand-mark"><ShieldIcon /></span>
          <span className="brand-name">
            <b>SpectonCR</b>
            <span>Registry &amp; scanner</span>
          </span>
        </Link>
        {nav}
        <div className="header-spacer" />
        {right}
        <button className="icon-btn" onClick={toggle} aria-label="Toggle color theme" title="Toggle theme">
          <SunMoon dark={isDark} />
        </button>
      </div>
    </header>
  );
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Normalize an API severity string ("HIGH", "Unknown", null) to a class key. */
export function sevKey(s?: string | null): Severity {
  const k = (s || 'unknown').toLowerCase();
  return (SEVERITIES as readonly string[]).includes(k) ? (k as Severity) : 'unknown';
}

export function SevBadge({ severity }: { severity?: string | null }) {
  const k = sevKey(severity);
  return <span className={`sev ${k}`}>{k}</span>;
}

export function SearchIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="11" cy="11" r="7" />
      <path d="m21 21-4.3-4.3" />
    </svg>
  );
}

/** Copy `value` to the clipboard, flashing a check for feedback. */
export function CopyButton({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard blocked (e.g. insecure context) — no-op */
    }
  }
  return (
    <button
      className={`copy ${copied ? 'copied' : ''}`}
      onClick={copy}
      title={copied ? 'Copied' : `Copy ${label ?? value}`}
      aria-label={`Copy ${label ?? value}`}
    >
      {copied ? (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="m5 12 5 5L20 7" />
        </svg>
      ) : (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <rect x="9" y="9" width="11" height="11" rx="2" />
          <path d="M5 15V5a2 2 0 0 1 2-2h10" />
        </svg>
      )}
    </button>
  );
}

/** Triage order for the findings table: severity desc, then CVSS desc. */
const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
export function sortBySeverity<T extends { severity: string; cvss_score?: number }>(rows: T[]): T[] {
  return [...rows].sort((a, b) => {
    const d = SEV_RANK[sevKey(a.severity)] - SEV_RANK[sevKey(b.severity)];
    return d !== 0 ? d : (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
  });
}

/** Stacked severity meter + directly-labelled legend (colour is never alone). */
export function SeverityBar({ summary }: { summary: Record<Severity, number> }) {
  const total = SEVERITIES.reduce((n, k) => n + (summary[k] ?? 0), 0);
  if (total === 0) return null;
  return (
    <div className="sevbar-wrap">
      <div className="sevbar" role="img" aria-label={SEVERITIES.map((k) => `${summary[k] ?? 0} ${k}`).join(', ')}>
        {SEVERITIES.map((k) => {
          const n = summary[k] ?? 0;
          if (n === 0) return null;
          return <span key={k} className={k} style={{ flexGrow: n }} title={`${n} ${k}`} />;
        })}
      </div>
      <div className="sevbar-legend">
        {SEVERITIES.map((k) => {
          const n = summary[k] ?? 0;
          return (
            <span key={k} className={`item ${n === 0 ? 'zero' : ''}`}>
              <span className="swatch" style={{ background: `var(--sev-${k})` }} />
              <b>{n}</b> {k}
            </span>
          );
        })}
      </div>
    </div>
  );
}
