// DELIBERATELY INSECURE sample QuickBooks app. It exists so the scanner has something real to catch.
// Never deploy it: it has an open redirect, echoes TRACE requests and serves pages over plain HTTP.
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import { handleConnect, handleCallback, handleToken } from './oauth.js';

const HTTPS_PORT = Number(process.env.HTTPS_PORT || 8443);
const HTTP_PORT = Number(process.env.HTTP_PORT || 8080);

function page(res, status, html, headers = {}) {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'x-powered-by': 'Express 4.17.1',
    ...headers,
  });
  res.end(html);
}

async function app(req, res) {
  const url = new URL(req.url, 'https://localhost');

  if (req.method === 'TRACE' || req.method === 'TRACK') {
    // Echoes the request back, headers included.
    res.writeHead(200, { 'content-type': 'message/http' });
    res.end(`${req.method} ${req.url} HTTP/1.1\r\n${Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n')}`);
    return;
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(200, { allow: 'GET, POST, PUT, DELETE, TRACE, OPTIONS' });
    res.end();
    return;
  }

  // "Return to where you were" after login, without checking where that is.
  const next = url.searchParams.get('next') || url.searchParams.get('returnTo');
  if (next) {
    res.writeHead(302, { location: next });
    res.end();
    return;
  }

  if (url.pathname === '/connect') return handleConnect(req, res);
  if (url.pathname === '/oauth/callback') return handleCallback(req, res, url);
  if (url.pathname === '/token') return handleToken(req, res);

  if (url.pathname === '/dashboard') {
    return page(res, 200, '<html><body><h1>Invoices</h1><p>Acme Corp owes $4,200.</p></body></html>', {
      'cache-control': 'private, max-age=0',
    });
  }

  page(res, 200, '<html><body><h1>Insecure sample app</h1><a href="/connect">Connect to QuickBooks</a></body></html>', {
    'set-cookie': 'sid=example-session-id; Path=/',
  });
}

const tls = {
  key: fs.readFileSync(process.env.TLS_KEY),
  cert: fs.readFileSync(process.env.TLS_CERT),
  // Still accepts TLS 1.0, as an old load balancer policy might.
  minVersion: 'TLSv1',
  ciphers: 'DEFAULT:@SECLEVEL=0',
};

https.createServer(tls, app).listen(HTTPS_PORT, () => console.log(`insecure-app https://localhost:${HTTPS_PORT}`));
// Serves the same app over plain HTTP instead of redirecting.
http.createServer(app).listen(HTTP_PORT, () => console.log(`insecure-app http://localhost:${HTTP_PORT}`));
