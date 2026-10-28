'use client';

import { useEffect, useState } from 'react';
import { MANUAL_CHECKS } from '@core/requirements.js';

const KEY = 'qbrc-attest';

export function Attest() {
  const [done, setDone] = useState<Record<number, boolean>>({});
  useEffect(() => {
    try {
      setDone(JSON.parse(localStorage.getItem(KEY) || '{}'));
    } catch {}
  }, []);
  const toggle = (i: number) => {
    const next = { ...done, [i]: !done[i] };
    setDone(next);
    try {
      localStorage.setItem(KEY, JSON.stringify(next));
    } catch {}
  };
  const n = MANUAL_CHECKS.filter((_, i) => done[i]).length;
  return (
    <div className="attest">
      <p className="progress tnum">{n === MANUAL_CHECKS.length ? `All ${n} confirmed` : `${n} of ${MANUAL_CHECKS.length} confirmed`}</p>
      <div className="attest-list">
        {MANUAL_CHECKS.map((m, i) => (
          <label key={i} htmlFor={`att-${i}`}>
            <input id={`att-${i}`} type="checkbox" checked={!!done[i]} onChange={() => toggle(i)} />
            <span>{m.prompt.replace(/`/g, '')}</span>
          </label>
        ))}
      </div>
    </div>
  );
}
