import { ImageResponse } from 'next/og';

export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';
export const alt = 'QuickBooks Review Check: free self-check for the QuickBooks app security review';

const rows: [string, string, string][] = [
  ['PASS', '#4fd18f', 'HTTP redirects to HTTPS'],
  ['PASS', '#4fd18f', 'TLS 1.0 and 1.1 rejected'],
  ['FAIL', '#ff7a6e', 'Cache-Control: private on /dashboard'],
  ['FAIL', '#ff7a6e', 'OAuth state is a constant'],
  ['WARN', '#f2c14e', 'Callback returns 400 without redirect'],
];

export default function OG() {
  return new ImageResponse(
    (
      <div style={{ width: '100%', height: '100%', display: 'flex', background: '#f4f5f9', padding: 64, gap: 48, fontFamily: 'sans-serif' }}>
        <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', flex: 1 }}>
          <div style={{ display: 'flex', fontSize: 22, color: '#4a5170', letterSpacing: 3, textTransform: 'uppercase' }}>Free · open source</div>
          <div style={{ display: 'flex', flexDirection: 'column', fontSize: 66, fontWeight: 800, color: '#141a2e', lineHeight: 1.05, letterSpacing: -2 }}>
            <span>Self-check your</span><span>QuickBooks app</span><span style={{ color: '#4f35c9' }}>before you submit.</span>
          </div>
          <div style={{ display: 'flex', fontSize: 24, color: '#4a5170' }}>QuickBooks Review Check · by Apideck</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', width: 470, background: '#10142a', borderRadius: 24, padding: 36, gap: 18, justifyContent: 'center' }}>
          {rows.map(([s, c, t]) => (
            <div key={t} style={{ display: 'flex', gap: 18, fontSize: 22, color: '#d7dbef', fontFamily: 'monospace' }}>
              <span style={{ color: c, width: 64 }}>{s}</span><span style={{ flex: 1 }}>{t}</span>
            </div>
          ))}
        </div>
      </div>
    ),
    size,
  );
}
