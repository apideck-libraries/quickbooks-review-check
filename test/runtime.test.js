import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { analyzeCacheControl, analyzeCookies, analyzeTokenEndpoint, analyzeTrace, analyzeHttpToHttps, analyzeTls, analyzeOpenRedirect, analyzeHsts } from '../src/runtime.js';
import { request } from '../src/http.js';

const res = (over = {}) => ({ url: 'https://app.test/dashboard', status: 200, headers: {}, setCookies: [], body: '', ...over });

test('cache-control: private is rejected, no-store passes', () => {
  assert.equal(analyzeCacheControl(res({ headers: { 'cache-control': 'private, max-age=0' } })).status, 'fail');
  assert.equal(analyzeCacheControl(res({ headers: { 'cache-control': 'no-store, no-cache' } })).status, 'pass');
  assert.equal(analyzeCacheControl(res(), { sensitive: false }).status, 'warn');
});

test('cookies: session cookie without HttpOnly fails, csrf cookie only needs Secure', () => {
  const out = analyzeCookies([res({ setCookies: ['connect.sid=abc; Path=/; Secure', 'XSRF-TOKEN=x; Secure; SameSite=Lax', 'theme=dark'] })]);
  const by = Object.fromEntries(out.map((r) => [r.id, r.status]));
  assert.equal(by['cookie:connect.sid'], 'fail');
  assert.equal(by['cookie:XSRF-TOKEN'], 'pass');
  assert.equal(by['cookie:theme'], 'warn');
});

test('token endpoint: HTML fails, 302 passes, token in Location fails', () => {
  const url = 'https://app.test/callback?code=x&realmId=1';
  assert.equal(analyzeTokenEndpoint(res({ url, headers: { 'content-type': 'text/html' }, body: '<html>ok</html>' })).status, 'fail');
  assert.equal(analyzeTokenEndpoint(res({ url, status: 302, headers: { location: '/app' } })).status, 'pass');
  assert.equal(analyzeTokenEndpoint(res({ url, status: 302, headers: { location: '/app?realmId=1' } })).status, 'fail');
  assert.equal(analyzeTokenEndpoint(res({ url, status: 422, headers: { 'content-type': 'application/json' }, body: '{"error":"x"}' })).status, 'pass');
  assert.equal(analyzeTokenEndpoint(res({ url, status: 200, headers: { 'content-type': 'application/json' }, body: '{}' })).status, 'warn');
});

test('hsts: passes when any probed response sets it', () => {
  const gateway = res({ url: 'https://api.test/', status: 403 });
  const route = res({ url: 'https://api.test/callback', headers: { 'strict-transport-security': 'max-age=31536000' } });
  assert.equal(analyzeHsts([gateway, route]).status, 'pass');
  assert.equal(analyzeHsts([gateway]).status, 'warn');
});

test('trace / http redirect / open redirect', () => {
  assert.equal(analyzeTrace(res({ status: 200, body: 'TRACE / HTTP/1.1' })).status, 'fail');
  assert.equal(analyzeTrace(res({ status: 405 })).status, 'pass');
  assert.equal(analyzeHttpToHttps({ url: 'http://a', status: 301, headers: { location: 'https://a/' } }).status, 'pass');
  assert.equal(analyzeHttpToHttps({ url: 'http://a', status: 200, headers: {} }).status, 'fail');
  assert.ok(analyzeOpenRedirect(res({ status: 302, headers: { location: 'https://evil.example.com/qbrc' } }), 'next'));
});

test('tls: accepting 1.0 fails, 1.1 warns', () => {
  const ok = { ok: true, cipher: { name: 'ECDHE-RSA-AES256-GCM-SHA384' }, authorized: true };
  const no = { ok: false, error: 'alert' };
  const a = analyzeTls({ v10: ok, v11: ok, v12: ok, v13: ok });
  assert.equal(a.find((r) => r.id === 'tls-1.0').status, 'fail');
  assert.equal(a.find((r) => r.id === 'tls-1.1').status, 'warn');
  const b = analyzeTls({ v10: no, v11: no, v12: ok, v13: no });
  assert.ok(b.every((r) => r.status === 'pass'));
});

test('request() supports TRACE against a live server', async () => {
  const srv = http.createServer((req, rs) => rs.writeHead(req.method === 'TRACE' ? 405 : 200).end());
  await new Promise((r) => srv.listen(0, r));
  const out = await request(`http://127.0.0.1:${srv.address().port}/`, { method: 'TRACE' });
  srv.close();
  assert.equal(out.status, 405);
});
