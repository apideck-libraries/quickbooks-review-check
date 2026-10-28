import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';

const BODY_LIMIT = 64 * 1024;

// Low-level request that never follows redirects and supports any method (fetch rejects TRACE).
export function request(url, { method = 'GET', headers = {}, timeout = 10000, insecure = false } = {}) {
  const u = new URL(url);
  const mod = u.protocol === 'http:' ? http : https;
  return new Promise((resolve, reject) => {
    const req = mod.request(
      u,
      {
        method,
        headers: { 'user-agent': 'quickbooks-review-check/0.1 (+https://github.com/apideck-libraries/quickbooks-review-check)', ...headers },
        timeout,
        rejectUnauthorized: !insecure,
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          if (size < BODY_LIMIT) chunks.push(c);
          size += c.length;
        });
        res.on('end', () => {
          const raw = res.headers['set-cookie'] || [];
          resolve({
            url,
            status: res.statusCode,
            headers: res.headers,
            setCookies: Array.isArray(raw) ? raw : [raw],
            body: Buffer.concat(chunks).toString('utf8').slice(0, BODY_LIMIT),
          });
        });
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error(`timeout after ${timeout}ms`)));
    req.on('error', reject);
    req.end();
  });
}

// Try a TLS handshake pinned to one protocol version. Resolves { ok, protocol, cipher } or { ok:false, error }.
// SECLEVEL=0 lets modern OpenSSL builds still *offer* TLS 1.0/1.1 so we can detect servers that accept them.
export function tlsHandshake(host, port, version, { timeout = 8000 } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => {
      if (!settled) {
        settled = true;
        resolve(v);
      }
    };
    let socket;
    try {
      socket = tls.connect({
        host,
        port,
        servername: host,
        minVersion: version,
        maxVersion: version,
        ciphers: version === 'TLSv1.3' ? undefined : 'DEFAULT:@SECLEVEL=0',
        rejectUnauthorized: false,
        timeout,
      });
    } catch (e) {
      return done({ ok: false, error: e.message, clientUnsupported: true });
    }
    socket.once('secureConnect', () => {
      const res = { ok: true, protocol: socket.getProtocol(), cipher: socket.getCipher(), authorized: socket.authorized, authError: socket.authorizationError };
      socket.end();
      done(res);
    });
    socket.once('timeout', () => {
      socket.destroy();
      done({ ok: false, error: 'timeout' });
    });
    socket.once('error', (e) => {
      // A client-side "no protocols available" means this Node/OpenSSL build cannot test the version.
      const clientUnsupported = /no protocols available|unsupported protocol/i.test(e.message) && !/alert/i.test(e.message);
      done({ ok: false, error: e.message, clientUnsupported });
    });
  });
}

// Parse a Set-Cookie header into { name, attrs: Set<lowercase attr names>, sameSite }.
export function parseSetCookie(header) {
  const parts = header.split(';').map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const name = nameValue.split('=')[0].trim();
  const attrNames = new Set();
  let sameSite = null;
  for (const a of attrs) {
    const [k, v] = a.split('=');
    const key = k.trim().toLowerCase();
    attrNames.add(key);
    if (key === 'samesite') sameSite = (v || '').trim().toLowerCase();
  }
  return { name, attrs: attrNames, sameSite, raw: header };
}

export function isHtml(res) {
  const ct = String(res.headers['content-type'] || '').toLowerCase();
  if (ct.includes('text/html') || ct.includes('application/xhtml')) return res.body.trim().length > 0;
  return /^\s*(<!doctype html|<html)/i.test(res.body);
}
