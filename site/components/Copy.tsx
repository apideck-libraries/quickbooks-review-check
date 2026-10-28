'use client';

import { useState } from 'react';

export function Copy({ text, className = 'copy' }: { text: string; className?: string }) {
  const [label, setLabel] = useState('Copy');
  return (
    <button
      type="button"
      className={className}
      onClick={() =>
        navigator.clipboard.writeText(text).then(
          () => setLabel('Copied'),
          () => setLabel('Copy failed'),
        ).finally(() => setTimeout(() => setLabel('Copy'), 1600))
      }
    >
      {label}
    </button>
  );
}
