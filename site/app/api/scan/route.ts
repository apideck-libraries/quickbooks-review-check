import { runRuntime } from '@core/runtime.js';
import { validateTarget, assertPublicHost, safeLookup, TargetError } from '@core/guard.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

const PATH_RE = /^\/(?!\/)[\w\-./~%]*$/;
const WINDOW_MS = 10 * 60 * 1000;
const MAX_SCANS = 8;
// Best-effort per-instance limit; pair with a Vercel Firewall rate-limit rule on /api/scan.
const hits = new Map<string, number[]>();

function limited(ip: string) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) hits.clear();
  return recent.length > MAX_SCANS;
}

const bad = (message: string, status = 400) => Response.json({ error: message }, { status, headers: { 'cache-control': 'no-store' } });

export async function POST(req: Request) {
  let body: { url?: string; callback?: string; path?: string; authorized?: boolean };
  try {
    body = await req.json();
  } catch {
    return bad('Send a JSON body.');
  }
  if (body.authorized !== true) return bad('Confirm that you own this app or are authorized to test it.');
  for (const p of [body.callback, body.path]) {
    if (p && (!PATH_RE.test(p) || p.length > 200)) return bad('Paths must start with a single "/" and contain no spaces, like /oauth/callback.');
  }

  let target: URL;
  try {
    target = validateTarget(String(body.url || '').trim());
    await assertPublicHost(target.hostname);
  } catch (e) {
    return bad(e instanceof TargetError ? e.message : 'Could not check that URL.');
  }

  const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || 'unknown';
  if (limited(ip)) return bad('Too many scans from your network. Try again in a few minutes, or run the CLI locally.', 429);

  const enc = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (msg: object) => controller.enqueue(enc.encode(`${JSON.stringify(msg)}\n`));
      send({ type: 'start', target: target.href });
      try {
        await runRuntime({
          url: target.href,
          paths: body.path ? [body.path] : [],
          callback: body.callback || undefined,
          timeout: 8000,
          lookup: safeLookup,
          onResult: (result: object) => send({ type: 'result', result }),
        });
        send({ type: 'done' });
      } catch {
        send({ type: 'error', message: 'The scan stopped unexpectedly. Try again, or run the CLI locally.' });
      }
      controller.close();
    },
  });

  return new Response(stream, {
    headers: { 'content-type': 'application/x-ndjson; charset=utf-8', 'cache-control': 'no-store', 'x-accel-buffering': 'no' },
  });
}
