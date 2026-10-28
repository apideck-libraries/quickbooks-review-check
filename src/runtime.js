import { request, tlsHandshake, parseSetCookie, isHtml } from './http.js';

const SESSION_COOKIE = /(sess|sid|auth|token|jwt|login|remember|connect\.sid|csrf|xsrf|identity|user)/i;
const EVIL = 'https://evil.example.com/qbrc';
const REDIRECT_PARAMS = ['redirect', 'redirect_uri', 'redirectUrl', 'next', 'returnTo', 'return_to', 'url', 'continue', 'dest'];

const r = (id, requirement, status, title, detail, extra = {}) => ({ id, requirement, status, title, detail, ...extra });

// ---------- pure analyzers (unit tested) ----------

export function analyzeHttpToHttps(outcome) {
  const req = 'https-everywhere';
  if (outcome.error) {
    return r('http-redirect', req, 'pass', 'Plain HTTP not served', `Port 80 refused or unreachable (${outcome.error}); no plaintext content served.`);
  }
  const loc = String(outcome.headers.location || '');
  if (outcome.status >= 300 && outcome.status < 400 && loc.startsWith('https://')) {
    const permanent = [301, 308].includes(outcome.status);
    return r('http-redirect', req, permanent ? 'pass' : 'warn', 'HTTP redirects to HTTPS',
      permanent ? `HTTP ${outcome.status} → ${loc}` : `HTTP ${outcome.status} → ${loc}. Prefer a permanent 301/308 redirect.`);
  }
  return r('http-redirect', req, 'fail', 'HTTP does not redirect to HTTPS',
    `GET ${outcome.url} returned ${outcome.status}${loc ? ` → ${loc}` : ''}. Every page must be served over HTTPS.`,
    { fix: 'Redirect all port-80 traffic to HTTPS with a 301 and enable HSTS.' });
}

// Takes every HTTPS response from the host: an API host often answers `/` from its gateway (a bare
// 403 without app headers) while the app's own routes do send HSTS.
export function analyzeHsts(responses) {
  const list = Array.isArray(responses) ? responses : [responses];
  const withHsts = list.find((res) => res.headers['strict-transport-security']);
  if (!withHsts) {
    const urls = list.map((res) => new URL(res.url).pathname).join(', ');
    return r('hsts', 'https-everywhere', 'warn', 'No Strict-Transport-Security header', `None of the probed responses (${urls}) set HSTS. Not an explicit Intuit item, but reviewers' scanners flag it.`, { fix: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.' });
  }
  const h = withHsts.headers['strict-transport-security'];
  const m = /max-age=(\d+)/i.exec(h);
  if (!m || Number(m[1]) < 15552000) return r('hsts', 'https-everywhere', 'warn', 'HSTS max-age is short', `HSTS: ${h} (recommend ≥ 6 months).`);
  return r('hsts', 'https-everywhere', 'pass', 'HSTS enabled', `${h} (on ${new URL(withHsts.url).pathname})`);
}

export function analyzeTls(results) {
  const out = [];
  const req = 'tls-version';
  const { v10, v11, v12, v13 } = results;
  if (v10?.ok) out.push(r('tls-1.0', req, 'fail', 'TLS 1.0 accepted', 'The server negotiates TLS 1.0, which is below Intuit\'s TLS 1.1 minimum.', { fix: 'Disable TLS 1.0 (and 1.1) on your load balancer / CDN.' }));
  else if (v10?.clientUnsupported) out.push(r('tls-1.0', req, 'skip', 'TLS 1.0 not testable', 'This Node/OpenSSL build cannot offer TLS 1.0.'));
  else out.push(r('tls-1.0', req, 'pass', 'TLS 1.0 rejected', v10?.error || 'Handshake refused.'));

  if (v11?.ok) out.push(r('tls-1.1', req, 'warn', 'TLS 1.1 accepted', 'TLS 1.1 meets Intuit\'s minimum but is deprecated; Intuit recommends TLS 1.2+.', { fix: 'Set the minimum protocol to TLS 1.2.' }));
  else if (v11?.clientUnsupported) out.push(r('tls-1.1', req, 'skip', 'TLS 1.1 not testable', 'This Node/OpenSSL build cannot offer TLS 1.1.'));
  else out.push(r('tls-1.1', req, 'pass', 'TLS 1.1 rejected', v11?.error || 'Handshake refused.'));

  if (!v12?.ok && !v13?.ok) {
    out.push(r('tls-modern', req, 'fail', 'No TLS 1.2/1.3 support', `TLS 1.2: ${v12?.error}; TLS 1.3: ${v13?.error}`));
  } else {
    const best = v13?.ok ? v13 : v12;
    const cipher = v12?.ok ? v12.cipher?.name : best.cipher?.name;
    const strong = !v12?.ok || /AES_?256|AES256|CHACHA20/i.test(cipher || '');
    out.push(r('tls-modern', req, strong ? 'pass' : 'warn', `${[v12?.ok && 'TLS 1.2', v13?.ok && 'TLS 1.3'].filter(Boolean).join(' + ')} supported`,
      `Negotiated cipher (TLS 1.2): ${cipher || 'n/a'}${strong ? '' : ' — Intuit recommends AES-256 with SHA-256.'}`));
    if (best.authorized === false) out.push(r('tls-cert', req, 'fail', 'Certificate not trusted', `Certificate validation failed: ${best.authError}`));
    else out.push(r('tls-cert', req, 'pass', 'Certificate trusted', 'Certificate chain validates against the system trust store.'));
  }
  return out;
}

export function analyzeCacheControl(res, { sensitive = true } = {}) {
  const req = 'cache-control';
  const id = `cache-control:${new URL(res.url).pathname}`;
  const cc = String(res.headers['cache-control'] || '').toLowerCase();
  const pragma = String(res.headers.pragma || '').toLowerCase();
  const dirs = new Set(cc.split(',').map((d) => d.trim().split('=')[0]).filter(Boolean));
  const path = new URL(res.url).pathname;
  if (res.status >= 300 && res.status < 400 && !cc) {
    return r(id, req, 'warn', `Cache-Control not checked on ${path}`, `${path} returned ${res.status} (redirect, probably to login). Pass --header "Cookie: …" to probe it authenticated.`);
  }
  if (dirs.has('no-store') && dirs.has('no-cache')) return r(id, req, 'pass', `Caching disabled on ${path}`, `Cache-Control: ${cc}`);
  if (dirs.has('no-store')) return r(id, req, 'pass', `Caching disabled on ${path}`, `Cache-Control: ${cc} (Intuit asks for both no-store and no-cache; adding no-cache is harmless).`);
  const status = sensitive ? 'fail' : 'warn';
  const why = dirs.has('private') ? '`private` is not accepted by Intuit — it still allows browser caching.' : cc ? 'Missing no-store.' : 'No Cache-Control header.';
  return r(id, req, status, `Sensitive page cacheable: ${path}`, `Cache-Control: ${cc || '(none)'}${pragma ? `, Pragma: ${pragma}` : ''}. ${why}`,
    { fix: 'Send `Cache-Control: no-store, no-cache, must-revalidate` and `Pragma: no-cache` on every authenticated or token-handling response.' });
}

export function analyzeCookies(responses) {
  const seen = new Map();
  for (const res of responses) for (const sc of res.setCookies || []) {
    const c = parseSetCookie(sc);
    if (!seen.has(c.name)) seen.set(c.name, { ...c, url: res.url });
  }
  if (seen.size === 0) return [r('cookies', 'cookie-flags', 'skip', 'No cookies observed', 'No Set-Cookie headers on probed URLs. Probe your login/callback with --path to see session cookies.')];
  const out = [];
  for (const c of seen.values()) {
    const missing = ['secure', 'httponly'].filter((a) => !c.attrs.has(a));
    const session = SESSION_COOKIE.test(c.name);
    // CSRF double-submit cookies must be JS-readable; only require Secure on them.
    const csrfToken = /csrf|xsrf/i.test(c.name);
    const required = csrfToken ? missing.filter((m) => m === 'secure') : missing;
    if (required.length === 0) {
      const ss = c.sameSite ? `SameSite=${c.sameSite}` : 'no SameSite (consider Lax)';
      out.push(r(`cookie:${c.name}`, 'cookie-flags', 'pass', `Cookie ${c.name} is Secure${csrfToken ? '' : ' + HttpOnly'}`, ss));
    } else {
      out.push(r(`cookie:${c.name}`, 'cookie-flags', session ? 'fail' : 'warn', `Cookie ${c.name} missing ${required.join(' + ')}`,
        `${session ? 'Looks like a session/auth cookie. ' : ''}Set-Cookie: ${c.raw.slice(0, 160)}`,
        { fix: 'Set `Secure; HttpOnly; SameSite=Lax` on session cookies (e.g. express-session `cookie: { secure: true, httpOnly: true }`).' }));
    }
  }
  return out;
}

export function analyzeTrace(outcome, method = 'TRACE') {
  const req = 'http-methods';
  if (outcome.error) return r(`method:${method}`, req, 'pass', `${method} refused`, `Connection rejected: ${outcome.error}`);
  const echoed = /^TRACE |x-qbrc-probe/i.test(outcome.body || '');
  if (outcome.status >= 200 && outcome.status < 300) {
    return r(`method:${method}`, req, 'fail', `${method} enabled`, `${method} ${outcome.url} → ${outcome.status}${echoed ? ' and echoed the request (Cross-Site Tracing)' : ''}.`,
      { fix: `Disable ${method} at the web server / load balancer (nginx: \`if ($request_method !~ ^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$) { return 405; }\`).` });
  }
  return r(`method:${method}`, req, 'pass', `${method} disabled`, `${method} → ${outcome.status}`);
}

export function analyzeAllow(outcome) {
  if (outcome.error) return null;
  const allow = String(outcome.headers.allow || outcome.headers['access-control-allow-methods'] || '');
  if (!allow) return null;
  const bad = allow.split(',').map((m) => m.trim().toUpperCase()).filter((m) => ['TRACE', 'TRACK', 'CONNECT'].includes(m));
  if (bad.length) return r('method:allow', 'http-methods', 'warn', `Server advertises ${bad.join(', ')}`, `OPTIONS Allow: ${allow}`);
  return r('method:allow', 'http-methods', 'info', 'Advertised methods', `OPTIONS Allow: ${allow}. Confirm each is actually used.`);
}

export function analyzeTokenEndpoint(res) {
  const req = 'token-endpoint-302';
  const path = new URL(res.url).pathname;
  const html = isHtml(res);
  const refPolicy = String(res.headers['referrer-policy'] || '').toLowerCase();
  const safeReferrer = /no-referrer|same-origin|strict-origin/.test(refPolicy);
  if (res.status >= 300 && res.status < 400) {
    const loc = String(res.headers.location || '');
    if (/[?&](code|access_token|refresh_token|realmId|id_token)=/i.test(loc)) {
      return r(`token-endpoint:${path}`, req, 'fail', `${path} forwards tokens in the redirect`, `Location: ${loc}`, { fix: 'Exchange the code server-side and redirect to a clean URL without token/realmId parameters.' });
    }
    return r(`token-endpoint:${path}`, req, 'pass', `${path} responds with ${res.status} redirect`, `Location: ${loc || '(none)'}`);
  }
  if (html) {
    return r(`token-endpoint:${path}`, req, 'fail', `${path} returns HTML with tokens in the URL`,
      `GET ${path}?code=…&realmId=… → ${res.status} text/html. Any third-party resource on that page receives the code and realmId via Referer.${safeReferrer ? ` (Referrer-Policy: ${refPolicy} mitigates, but Intuit still requires a redirect.)` : ''}`,
      { fix: 'Handle the callback server-side and always answer with `302 Found` — on success and on error (redirect to an error page without the parameters).' });
  }
  // An error for a request it cannot place (unknown state, missing code) has nowhere safe to
  // redirect to. What the rule guards against is HTML in the response, which a non-HTML error avoids.
  if (res.status >= 400) {
    return r(`token-endpoint:${path}`, req, 'pass', `${path} answers invalid requests without HTML`, `GET ${path} with a fake code and state → ${res.status} ${res.headers['content-type'] || ''}. No page is rendered, so nothing can leak through Referer. A real authorization should still end in a 302; test that with a real connect flow.`);
  }
  return r(`token-endpoint:${path}`, req, 'warn', `${path} returns ${res.status} without redirect`, `Body is not HTML (${res.headers['content-type'] || 'no content-type'}), so Referer leakage is unlikely, but Intuit expects a 302.`);
}

export function analyzeOpenRedirect(res, param) {
  const loc = String(res.headers.location || '');
  if (res.status >= 300 && res.status < 400 && loc.startsWith(EVIL)) {
    // The same parameter can be open on several paths; keep one result per path and parameter.
    const path = new URL(res.url).pathname;
    return r(`open-redirect:${path}?${param}`, 'open-redirect', 'fail', `Open redirect via ${path}?${param}=`, `${res.url} → ${loc}`, { fix: 'Only redirect to relative paths or an allow-list of hosts.' });
  }
  return null;
}

export function analyzeDisclosure(res) {
  const out = [];
  const server = res.headers.server;
  const powered = res.headers['x-powered-by'];
  const versioned = [server, powered].filter((h) => h && /\d+\.\d+/.test(h));
  if (versioned.length) out.push(r('disclosure', 'patching-logging', 'warn', 'Server version disclosed', `${versioned.join(' / ')} — reviewers use this to flag unpatched software.`, { fix: 'Hide version banners (nginx `server_tokens off;`, Express `app.disable("x-powered-by")`).' }));
  else if (powered) out.push(r('disclosure', 'patching-logging', 'info', 'X-Powered-By header present', `X-Powered-By: ${powered}`));
  return out;
}

export function analyzeSecurityHeaders(res) {
  const missing = [];
  const csp = String(res.headers['content-security-policy'] || '');
  if (!/frame-ancestors/.test(csp) && !res.headers['x-frame-options']) missing.push('X-Frame-Options or CSP frame-ancestors (clickjacking)');
  if (!res.headers['x-content-type-options']) missing.push('X-Content-Type-Options: nosniff');
  if (!csp) missing.push('Content-Security-Policy (XSS defense in depth)');
  if (!missing.length) return r('security-headers', 'xss', 'pass', 'Browser security headers present', 'CSP, framing and nosniff headers set.');
  return r('security-headers', 'xss', 'warn', 'Missing browser security headers', missing.join('; '), { fix: 'Use helmet (Node), secure_headers (Rails) or equivalent.' });
}

// ---------- probes ----------

async function safe(fn) {
  try {
    return await fn();
  } catch (e) {
    return { error: e.code || e.message };
  }
}

/**
 * @param {{ url: string, paths?: string[], callback?: string, headers?: Record<string, string>, timeout?: number,
 *   log?: (m: string) => void, onResult?: (r: object) => void, lookup?: Function, httpPort?: number }} opts
 */
// onResult streams each result as soon as it is known; lookup lets a hosted scanner pin DNS to vetted IPs.
export async function runRuntime({ url, paths = [], callback, headers = {}, timeout = 10000, log = () => {}, onResult, lookup, httpPort }) {
  const base = new URL(url);
  if (base.protocol !== 'https:') base.protocol = 'https:';
  const results = [];
  const push = (...items) => {
    for (const item of items) {
      results.push(item);
      onResult?.(item);
    }
  };
  const responses = [];
  const at = (p) => new URL(p, base).toString();

  log(`GET ${base.href}`);
  const home = await safe(() => request(base.href, { headers, timeout, lookup }));
  if (home.error) {
    push(r('reachable', 'https-everywhere', 'fail', 'HTTPS endpoint unreachable', `${base.href}: ${home.error}`));
    return results;
  }
  responses.push(home);

  // HTTPS everywhere
  const httpUrl = new URL(base.href);
  httpUrl.protocol = 'http:';
  // Plain HTTP on port 80 unless told otherwise (local test servers run on high ports).
  httpUrl.port = httpPort ? String(httpPort) : '';
  log(`GET ${httpUrl.href}`);
  const plain = await safe(() => request(httpUrl.href, { timeout, lookup }));
  push(analyzeHttpToHttps({ url: httpUrl.href, ...plain }));

  // TLS
  const port = Number(base.port || 443);
  log(`TLS handshakes ${base.hostname}:${port}`);
  const [v10, v11, v12, v13] = await Promise.all(['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'].map((v) => tlsHandshake(base.hostname, port, v, { lookup })));
  push(...analyzeTls({ v10, v11, v12, v13 }));

  // Cache-Control on sensitive pages (user-specified; else the callback and home page)
  const sensitive = paths.length ? paths : [base.pathname];
  for (const p of sensitive) {
    const target = at(p);
    log(`GET ${target}`);
    const res = p === base.pathname ? home : await safe(() => request(target, { headers, timeout, lookup }));
    if (res.error) {
      push(r(`cache-control:${p}`, 'cache-control', 'warn', `Could not fetch ${p}`, res.error));
      continue;
    }
    if (res !== home) responses.push(res);
    push(analyzeCacheControl(res, { sensitive: paths.length > 0 }));
  }

  // HTTP methods
  for (const m of ['TRACE', 'TRACK']) {
    log(`${m} ${base.href}`);
    const res = await safe(() => request(base.href, { method: m, headers: { 'x-qbrc-probe': '1' }, timeout, lookup }));
    push(analyzeTrace(res.error ? { ...res, url: base.href } : res, m));
  }
  const opt = await safe(() => request(base.href, { method: 'OPTIONS', timeout, lookup }));
  const allow = analyzeAllow(opt);
  if (allow) push(allow);

  // Token endpoint / OAuth callback
  if (callback) {
    const cb = new URL(at(callback));
    cb.searchParams.set('code', 'QBRC_FAKE_AUTH_CODE');
    cb.searchParams.set('state', 'qbrc-probe-state');
    cb.searchParams.set('realmId', '9130000000000000');
    log(`GET ${cb.href}`);
    const res = await safe(() => request(cb.href, { headers: { ...headers, referer: 'https://appcenter.intuit.com/' }, timeout, lookup }));
    if (res.error) push(r('token-endpoint', 'token-endpoint-302', 'warn', 'Callback unreachable', `${cb.href}: ${res.error}`));
    else if (res.status === 404) push(r('token-endpoint', 'token-endpoint-302', 'warn', `Callback ${callback} returned 404`, 'Check the --callback path matches the Redirect URI registered in the Intuit developer portal.'));
    else {
      responses.push(res);
      push(analyzeTokenEndpoint(res));
      push(analyzeCacheControl(res, { sensitive: true }));
    }
  } else {
    push(r('token-endpoint', 'token-endpoint-302', 'skip', 'OAuth callback not probed', 'Pass --callback /your/oauth/callback to verify the 302 rule.'));
  }

  // Open redirects on home and callback
  const redirectTargets = [base.pathname, callback].filter(Boolean);
  const probes = redirectTargets.flatMap((p) => REDIRECT_PARAMS.map((param) => ({ p, param })));
  const found = await Promise.all(probes.map(async ({ p, param }) => {
    const u = new URL(at(p));
    u.searchParams.set(param, EVIL);
    const res = await safe(() => request(u.href, { headers, timeout, lookup }));
    return res.error ? null : analyzeOpenRedirect(res, param);
  }));
  const hits = found.filter(Boolean);
  push(...hits);
  const openRedirect = hits.length > 0;
  if (!openRedirect) push(r('open-redirect', 'open-redirect', 'pass', 'No open redirect found', `Probed ${REDIRECT_PARAMS.length} common redirect parameters on ${redirectTargets.join(', ')}.`));

  push(analyzeHsts(responses.filter((res) => res.url.startsWith('https:'))));
  push(...analyzeCookies(responses));
  push(...analyzeDisclosure(home));
  push(analyzeSecurityHeaders(home));
  return results;
}
