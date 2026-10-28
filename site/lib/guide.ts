// Long-form guidance per requirement for /checklist. Requirement text is our paraphrase of Intuit's public docs.
export type GuideItem = { id: string; why: string; check?: string; fixes?: [string, string][]; tool: 'auto' | 'heuristic' | 'manual' };

export const GUIDE: Record<string, GuideItem[]> = {
  transport: [
    {
      id: 'https-everywhere', tool: 'auto',
      why: 'Every page, including marketing pages on the same host, should only be reachable over HTTPS. Plain HTTP should redirect permanently.',
      check: 'curl -sI http://app.example.com | grep -iE "^(HTTP|location)"\n# expect: HTTP/1.1 301 … and location: https://…',
      fixes: [
        ['nginx', 'server {\n  listen 80;\n  server_name app.example.com;\n  return 301 https://$host$request_uri;\n}\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'],
        ['Express', "app.set('trust proxy', 1);\napp.use((req, res, next) =>\n  req.secure ? next() : res.redirect(301, `https://${req.headers.host}${req.url}`));"],
      ],
    },
    {
      id: 'tls-version', tool: 'auto',
      why: 'TLS 1.0 is below the minimum, and TLS 1.1 is deprecated everywhere else. Most managed platforms (Vercel, Cloudflare, AWS ALB with a modern policy) already refuse both.',
      check: 'openssl s_client -connect app.example.com:443 -tls1_1 </dev/null 2>&1 | grep -E "Protocol|alert"\n# a handshake failure here is what you want',
      fixes: [
        ['nginx', 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;'],
        ['AWS ALB', 'Use the security policy ELBSecurityPolicy-TLS13-1-2-2021-06 (or newer) on the HTTPS listener.'],
      ],
    },
    {
      id: 'cache-control', tool: 'auto',
      why: '`private` only stops shared caches; the browser can still store the page on disk. Anything showing QuickBooks data, tokens or account settings needs `no-store`.',
      check: 'curl -sI -H "Cookie: session=…" https://app.example.com/dashboard | grep -i cache-control\n# expect: no-store (and no-cache)',
      fixes: [
        ['Express', "app.use(['/app', '/oauth'], (req, res, next) => {\n  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');\n  res.set('Pragma', 'no-cache');\n  next();\n});"],
        ['Next.js', "// next.config.js\nheaders: async () => [{\n  source: '/app/:path*',\n  headers: [{ key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate' }],\n}]"],
        ['Django', 'from django.views.decorators.cache import never_cache\n\n@never_cache\ndef dashboard(request): ...'],
      ],
    },
    {
      id: 'http-methods', tool: 'auto',
      why: 'TRACE echoes the request back, including headers, which enables cross-site tracing. Turn off any method your app does not serve.',
      check: 'curl -si -X TRACE https://app.example.com/ | head -1\n# expect 405 or 501, not 200',
      fixes: [
        ['nginx', 'if ($request_method !~ ^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$) {\n  return 405;\n}'],
        ['Apache', 'TraceEnable off'],
      ],
    },
    {
      id: 'patching-logging', tool: 'heuristic',
      why: 'Logs are often shipped to third-party services and kept for a long time. A logged refresh token is a working credential to a customer’s books.',
      fixes: [
        ['Node', "// log a fingerprint, never the token\nlogger.info({ realm: hash(realmId), tokenTail: token.refresh_token.slice(-4) }, 'token refreshed');"],
      ],
    },
  ],
  attacks: [
    {
      id: 'csrf', tool: 'heuristic',
      why: 'Intuit’s sample code passes a fixed `state` value. Shipping that means anyone can make a victim’s browser connect the attacker’s QuickBooks company to the victim’s account.',
      fixes: [
        ['Node (intuit-oauth)', "// /connect\nreq.session.oauthState = crypto.randomBytes(32).toString('hex');\nres.redirect(oauthClient.authorizeUri({ scope, state: req.session.oauthState }));\n\n// /callback\nif (!req.query.state || req.query.state !== req.session.oauthState) return res.redirect('/error');\ndelete req.session.oauthState;"],
      ],
    },
    { id: 'xss', tool: 'heuristic', why: 'Customer names, memos and line descriptions come from QuickBooks users and can contain markup. Escape them like any other user input.' },
    { id: 'injection', tool: 'heuristic', why: 'This applies to your database and also to QuickBooks query strings. A customer name like O’Brien breaks an unescaped `WHERE DisplayName = \'…\'` query.' },
    { id: 'auth-session', tool: 'manual', why: 'The most common real-world issue is an insecure direct object reference: changing a realmId or record id in a request shows another customer’s data. Check that ownership is enforced on every route.' },
    { id: 'open-redirect', tool: 'auto', why: 'Login and OAuth flows often take a `next` or `returnTo` parameter. Only allow relative paths or an allow-list of hosts.' },
  ],
  cookies: [
    {
      id: 'cookie-flags', tool: 'auto',
      why: '`Secure` keeps the cookie off plain HTTP. `HttpOnly` keeps it away from JavaScript, so an XSS bug can’t steal the session.',
      check: 'curl -sI https://app.example.com/login | grep -i set-cookie',
      fixes: [
        ['express-session', "session({ cookie: { secure: true, httpOnly: true, sameSite: 'lax' }, proxy: true, ... })"],
        ['Django', 'SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nCSRF_COOKIE_SECURE = True'],
        ['Rails', "Rails.application.config.session_store :cookie_store, secure: true, httponly: true, same_site: :lax"],
      ],
    },
  ],
  oauth: [
    { id: 'token-exposure', tool: 'heuristic', why: 'Tokens belong on the server. The browser should only ever hold an opaque session cookie, and a disconnect should revoke the tokens with Intuit.' },
    {
      id: 'token-encryption', tool: 'heuristic',
      why: 'The refresh token lasts for months and the realmId identifies the company. Both need encrypting before they reach your database or cache.',
      fixes: [
        ['Node (AES-256-GCM)', "import crypto from 'node:crypto';\nconst key = Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, 'base64'); // 32 bytes\n\nexport function encrypt(plain) {\n  const iv = crypto.randomBytes(12);\n  const c = crypto.createCipheriv('aes-256-gcm', key, iv);\n  const data = Buffer.concat([c.update(plain, 'utf8'), c.final()]);\n  return Buffer.concat([iv, c.getAuthTag(), data]).toString('base64');\n}\n\nexport function decrypt(blob) {\n  const buf = Buffer.from(blob, 'base64');\n  const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));\n  d.setAuthTag(buf.subarray(12, 28));\n  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');\n}"],
        ['Python (cryptography)', "import os, base64\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\nkey = base64.b64decode(os.environ['TOKEN_ENCRYPTION_KEY'])\n\ndef encrypt(plain: str) -> str:\n    nonce = os.urandom(12)\n    return base64.b64encode(nonce + AESGCM(key).encrypt(nonce, plain.encode(), None)).decode()"],
        ['Rails', 'class QuickbooksConnection < ApplicationRecord\n  encrypts :refresh_token\n  encrypts :realm_id, deterministic: true\nend'],
      ],
    },
    { id: 'key-storage', tool: 'heuristic', why: 'A key committed next to the ciphertext protects nothing. Load it from an environment variable, a config file outside the repo, or a secrets manager, and plan for rotation.' },
  ],
  redirect: [
    {
      id: 'token-endpoint-302', tool: 'auto',
      why: 'Intuit sends the user back to your redirect URI with `code` and `realmId` in the query string. If that URL renders a page with any third-party asset (analytics, fonts, a CDN image), the browser can send the full URL in the Referer header.',
      check: 'curl -si "https://app.example.com/oauth/callback?code=x&state=y&realmId=1" | grep -iE "^(HTTP|location|content-type)"\n# expect: HTTP/1.1 302 and a location without code/realmId',
      fixes: [
        ['Express', "app.get('/oauth/callback', async (req, res) => {\n  try {\n    await handleCallback(req);          // validate state, exchange code, store encrypted\n    res.redirect(302, '/app/connected');\n  } catch {\n    res.redirect(302, '/app/connect-error'); // errors redirect too\n  }\n});"],
      ],
    },
  ],
  data: [
    { id: 'no-third-party-access', tool: 'manual', why: 'This includes indirect sharing: sending invoices to an LLM API, piping payloads into product analytics, or error trackers capturing request bodies. Review every outbound integration that sits next to QuickBooks data.' },
    { id: 'data-minimization', tool: 'manual', why: 'Keep only what the feature needs, set retention periods, and delete data when a customer disconnects.' },
  ],
};
