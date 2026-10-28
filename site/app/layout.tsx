import type { Metadata } from 'next';
import Link from 'next/link';
import { Bricolage_Grotesque, IBM_Plex_Sans, IBM_Plex_Mono } from 'next/font/google';
import { SITE_URL, REPO } from '@/lib/site';
import './globals.css';

const display = Bricolage_Grotesque({ subsets: ['latin'], weight: ['500', '700', '800'], variable: '--font-display' });
const body = IBM_Plex_Sans({ subsets: ['latin'], weight: ['400', '500', '600'], variable: '--font-body' });
const mono = IBM_Plex_Mono({ subsets: ['latin'], weight: ['400', '500', '600'], variable: '--font-mono' });


export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: 'QuickBooks App Security Review Self-Check · Free tool by Apideck', template: '%s · QuickBooks Review Check' },
  description: 'Free, open-source self-check for the QuickBooks Online app security review. Scan your deployed app and your code for common review blockers: cache headers, cookie flags, TLS, OAuth token storage and more.',
  openGraph: { type: 'website', siteName: 'QuickBooks Review Check by Apideck' },
  twitter: { card: 'summary_large_image' },
};

function Logo() {
  return (
    <svg width="28" height="28" viewBox="0 0 28 28" aria-hidden>
      <rect x="1" y="1" width="26" height="26" rx="7" fill="var(--ink)" />
      <path d="M8 14.5l4 4 8-9" fill="none" stroke="var(--paper)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${display.variable} ${body.variable} ${mono.variable}`}>
      <body>
        <header className="top">
          <div className="wrap">
            <Link className="brand" href="/">
              <Logo />
              <span>QuickBooks Review Check <small>by Apideck</small></span>
            </Link>
            <nav className="nav" aria-label="Main">
              <Link href="/#checks">Checks</Link>
              <Link href="/checklist">Requirements guide</Link>
              <Link href="/#ci">GitHub Action</Link>
              <Link href="/#faq">FAQ</Link>
              <a className="gh" href={REPO}>GitHub</a>
            </nav>
          </div>
        </header>
        {children}
        <footer className="wrap foot">
          <div className="row-f">
            <span>An open-source project by <a href="https://www.apideck.com">Apideck</a> · MIT License</span>
            <nav aria-label="Footer">
              <Link href="/checklist">Requirements guide</Link>
              <a href={REPO}>Source</a>
              <a href={`${REPO}/issues`}>Report an issue</a>
            </nav>
          </div>
          <div className="legal">
            <p>This tool is provided &quot;as is&quot;, without warranty of any kind, under the MIT License. It is a self-assessment aid and is not legal, compliance or security advice. Results don&apos;t guarantee that an app meets Intuit&apos;s requirements or will be approved. You are responsible for your app&apos;s security and for confirming requirements against Intuit&apos;s official developer documentation. Only scan systems you own or are authorized to test.</p>
            <p>Not affiliated with, endorsed by or sponsored by Intuit Inc. Intuit and QuickBooks are trademarks of Intuit Inc., used here only to describe what the tool checks against. All other trademarks belong to their owners.</p>
          </div>
        </footer>
      </body>
    </html>
  );
}
