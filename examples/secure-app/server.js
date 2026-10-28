// Sample QuickBooks app that follows the security-review requirements the scanner checks.
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { handleConnect, handleCallback } from './oauth.js';

const HTTPS_PORT = Number(process.env.HTTPS_PORT || 9443);
const HTTP_PORT = Number(process.env.HTTP_PORT || 9080);
const ALLOWED_METHODS = 'GET, HEAD, POST, OPTIONS';

const SECURITY_HEADERS = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
};
export const NO_STORE = { 'cache-control': 'no-store, no-cache, must-revalidate', pragma: 'no-cache' };

export function serializeCookie(name, value, options = { secure: true, httpOnly: true, sameSite: 'Lax' }) {
  return [`${name}=${value}`, 'Path=/', options.secure && 'Secure', options.httpOnly && 'HttpOnly', `SameSite=${options.sameSite}`]
    .filter(Boolean)
    .join('; ');
}

// In-memory sessions keyed by an opaque cookie.
export const sessions = new Map();
export function session(req, res) {
  const sid = /(?:^|;\s*)sid=([\w-]+)/.exec(req.headers.cookie || '')?.[1];
  if (sid && sessions.has(sid)) return sessions.get(sid);
  const id = crypto.randomUUID();
  const data = {};
  sessions.set(id, data);
  res.setHeader('set-cookie', serializeCookie('sid', id));
  return data;
}

// Only same-site relative paths, so ?next= cannot send users to another site.
const safeNext = (value) => (value && value.startsWith('/') && !value.startsWith('//') ? value : '/');

async function app(req, res) {
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
  if (!ALLOWED_METHODS.split(', ').includes(req.method)) {
    res.writeHead(405, { allow: ALLOWED_METHODS });
    res.end();
    return;
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { allow: ALLOWED_METHODS });
    res.end();
    return;
  }

  const url = new URL(req.url, 'https://localhost');
  const s = session(req, res);

  if (url.pathname === '/connect') return handleConnect(req, res, s);
  if (url.pathname === '/oauth/callback') return handleCallback(req, res, url, s);
  if (url.pathname === '/login/done') {
    res.writeHead(302, { location: safeNext(url.searchParams.get('next')), ...NO_STORE });
    res.end();
    return;
  }
  if (url.pathname === '/dashboard') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', ...NO_STORE });
    res.end('<html><body><h1>Invoices</h1></body></html>');
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end('<html><body><h1>Secure sample app</h1><a href="/connect">Connect to QuickBooks</a></body></html>');
}

const tls = {
  key: fs.readFileSync(process.env.TLS_KEY),
  cert: fs.readFileSync(process.env.TLS_CERT),
  minVersion: 'TLSv1.2',
  // AES-256 first, as Intuit recommends.
  ciphers: 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305',
  honorCipherOrder: true,
};

https.createServer(tls, app).listen(HTTPS_PORT, () => console.log(`secure-app https://localhost:${HTTPS_PORT}`));
// Plain HTTP only redirects to HTTPS.
http
  .createServer((req, res) => {
    res.writeHead(301, { location: `https://localhost:${HTTPS_PORT}${req.url}` });
    res.end();
  })
  .listen(HTTP_PORT, () => console.log(`secure-app http://localhost:${HTTP_PORT}`));
