'use client';

import { useState } from 'react';
import { CATEGORIES, REQUIREMENTS } from '@core/requirements.js';
import { toMarkdown } from '@core/report.js';

export type Location = { file: string; line: number; snippet?: string };
export type Result = {
  id: string;
  requirement: string;
  status: 'pass' | 'fail' | 'warn' | 'info' | 'skip';
  title: string;
  detail: string;
  fix?: string;
  locations?: Location[];
};

const ORDER = { fail: 0, warn: 1, pass: 2, info: 3, skip: 4 } as const;
const LABEL = { pass: 'Pass', fail: 'Fail', warn: 'Warn', info: 'Info', skip: 'Skip' } as const;
const CATS = CATEGORIES as Record<string, string>;
const REQS = REQUIREMENTS as Record<string, { category: string; title: string }>;

export function Report({ results, running, label, target, source }: { results: Result[]; running?: boolean; label?: string; target?: string; source?: string }) {
  const [open, setOpen] = useState<string | null>(null);
  const counts = { pass: 0, fail: 0, warn: 0, info: 0, skip: 0 };
  for (const r of results) counts[r.status]++;
  const scored = counts.pass + counts.fail + counts.warn;

  const groups = Object.keys(CATS)
    .map((cat) => ({ cat, items: results.filter((r) => (REQS[r.requirement]?.category || 'transport') === cat).sort((a, b) => ORDER[a.status] - ORDER[b.status]) }))
    .filter((g) => g.items.length);

  const download = () => {
    const md = toMarkdown({ target, source, results });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([md], { type: 'text/markdown' }));
    a.download = 'quickbooks-review-check.md';
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="report" aria-live="polite" aria-busy={running}>
      <div className="report-head">
        <div className="tally">
          <span className="tally-num tnum">{counts.pass}<small>/{scored || '–'}</small></span>
          <span className="tally-label">{running ? 'checks running…' : 'checks passing'}</span>
        </div>
        <div className="bar" role="img" aria-label={`${counts.pass} passed, ${counts.fail} failed, ${counts.warn} warnings`}>
          {scored > 0 && (
            <>
              <i className="s-fail" style={{ flexGrow: counts.fail }} />
              <i className="s-warn" style={{ flexGrow: counts.warn }} />
              <i className="s-pass" style={{ flexGrow: counts.pass }} />
            </>
          )}
          {running && <i className="s-run" />}
        </div>
        <div className="chips tnum">
          <span className="chip-s fail">{counts.fail} fail</span>
          <span className="chip-s warn">{counts.warn} warn</span>
          <span className="chip-s pass">{counts.pass} pass</span>
          {label && <span className="chip-s note">{label}</span>}
        </div>
      </div>

      <div className="report-body">
        {groups.length === 0 && <p className="empty">{running ? 'Connecting…' : 'No results yet.'}</p>}
        {groups.map((g) => (
          <section key={g.cat} className="cat">
            <h4>{CATS[g.cat]}</h4>
            <ul>
              {g.items.map((r) => {
                const expandable = r.status !== 'pass' || !!r.locations?.length;
                const isOpen = open === r.id;
                return (
                  <li key={r.id} className={`row st-${r.status}`}>
                    <button type="button" className="row-btn" onClick={() => expandable && setOpen(isOpen ? null : r.id)} aria-expanded={expandable ? isOpen : undefined} disabled={!expandable}>
                      <span className={`badge ${r.status}`}>{LABEL[r.status]}</span>
                      <span className="row-title">{r.title}</span>
                      {expandable && <span className="caret" aria-hidden>{isOpen ? '−' : '+'}</span>}
                    </button>
                    {isOpen && (
                      <div className="row-detail">
                        <p>{r.detail}</p>
                        {r.fix && <p className="fix"><b>Fix</b> {r.fix}</p>}
                        {!!r.locations?.length && (
                          <ul className="locs">
                            {r.locations.slice(0, 8).map((l, i) => (
                              <li key={i}><code>{l.file}:{l.line}</code>{l.snippet && <pre>{l.snippet}</pre>}</li>
                            ))}
                          </ul>
                        )}
                        {REQS[r.requirement] && <p className="req">Review item: {REQS[r.requirement].title}</p>}
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          </section>
        ))}
      </div>

      {!running && results.length > 0 && !label && (
        <div className="report-foot">
          <button type="button" className="btn-sm" onClick={download}>Download report (.md)</button>
          <span>Includes the manual sign-off checklist.</span>
        </div>
      )}
    </div>
  );
}
