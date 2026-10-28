import type { Metadata } from 'next';
import Link from 'next/link';
import { CATEGORIES, REQUIREMENTS } from '@core/requirements.js';
import { GUIDE } from '@/lib/guide';

export const metadata: Metadata = {
  title: 'QuickBooks App Security Review Requirements Checklist',
  description: 'Every QuickBooks Online app security-review requirement in plain terms, with a command to check each one and fixes for Express, Next.js, nginx, Django and Rails.',
  alternates: { canonical: '/checklist' },
};

const CATS = CATEGORIES as Record<string, string>;
const REQS = REQUIREMENTS as Record<string, { title: string; text: string }>;
const TOOL = { auto: ['automated', 'auto'], heuristic: ['heuristic', 'part'], manual: ['sign-off', 'man'] } as const;

export default function Checklist() {
  const cats = Object.keys(GUIDE);
  return (
    <main>
      <section className="guide-hero">
        <div className="wrap">
          <p className="eyebrow">Requirements guide · updated October 2026</p>
          <h1>The QuickBooks app security review, item by item</h1>
          <p>What each requirement asks, why reviewers care, how to check it yourself in a terminal, and how to fix it in common stacks. Want it done for you? <Link href="/">Run the free scanner</Link>.</p>
          <div className="callout" style={{ marginTop: 28, maxWidth: '72ch' }}>
            This guide is our plain-language reading of Intuit’s published security requirements and isn’t official guidance. Requirements change, so confirm the current list in{' '}
            <a href="https://developer.intuit.com/app/developer/qbo/docs/go-live/publish-app/security-requirements">Intuit’s developer documentation</a> before you submit.
          </div>
        </div>
      </section>

      <div className="wrap guide">
        <nav className="toc" aria-label="On this page">
          {cats.map((c) => (
            <div key={c}>
              <b><a href={`#${c}`} style={{ color: 'inherit' }}>{CATS[c]}</a></b>
              {GUIDE[c].map((g) => <a key={g.id} href={`#${g.id}`}>{REQS[g.id].title}</a>)}
            </div>
          ))}
        </nav>

        <div className="guide-body">
          {cats.map((c) => (
            <section key={c} id={c} className="guide-cat" style={{ scrollMarginTop: 84 }}>
              <h2>{CATS[c]}</h2>
              {GUIDE[c].map((g) => {
                const [label, cls] = TOOL[g.tool];
                return (
                  <article key={g.id} id={g.id} className="req-item">
                    <h3>{REQS[g.id].title} <span className={`chip ${cls}`}>{label}</span></h3>
                    <p className="ask">{REQS[g.id].text}</p>
                    <p className="why">{g.why}</p>
                    {g.check && (<><h5>Check it yourself</h5><pre>{g.check}</pre></>)}
                    {g.fixes && (
                      <>
                        <h5>Fix it</h5>
                        <div className="stack">
                          {g.fixes.map(([stack, code], i) => (
                            <details key={stack} open={i === 0}><summary>{stack}</summary><pre>{code}</pre></details>
                          ))}
                        </div>
                      </>
                    )}
                  </article>
                );
              })}
            </section>
          ))}
        </div>
      </div>
    </main>
  );
}
