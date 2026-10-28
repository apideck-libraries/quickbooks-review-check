// End to end: start both sample apps over real TLS, run the CLI against them, and check that
// every runtime and source check fires on the insecure app and passes on the secure one.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeCerts } from '../examples/certs.js';
import { scanSource } from '../src/source.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const procs = [];
let certs;
const apps = {};

const freePort = () =>
  new Promise((resolve) => {
    const s = net.createServer().listen(0, () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

async function startApp(name) {
  const [httpsPort, httpPort] = [await freePort(), await freePort()];
  const child = spawn(process.execPath, [path.join(root, 'examples', name, 'server.js')], {
    env: { ...process.env, HTTPS_PORT: String(httpsPort), HTTP_PORT: String(httpPort), TLS_KEY: certs.key, TLS_CERT: certs.cert },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  procs.push(child);
  await new Promise((resolve, reject) => {
    let out = '';
    child.stdout.on('data', (d) => {
      out += d;
      if (out.includes('https://') && out.includes('http://')) resolve();
    });
    child.on('exit', (code) => reject(new Error(`${name} exited with ${code}`)));
  });
  apps[name] = { httpsPort, httpPort };
}

function scan(name) {
  const { httpsPort, httpPort } = apps[name];
  const args = [path.join(root, 'bin', 'quickbooks-review-check.js'), '--url', `https://localhost:${httpsPort}`, '--http-port', String(httpPort),
    '--callback', '/oauth/callback', '--path', '/dashboard', '--json', '-', '--quiet', '--fail-on', 'never'];
  return new Promise((resolve, reject) => {
    execFile(process.execPath, args, { env: { ...process.env, NODE_EXTRA_CA_CERTS: certs.ca } }, (err, stdout) => {
      if (err) return reject(err);
      try {
        resolve(JSON.parse(stdout).results);
      } catch (e) {
        reject(new Error(`${e.message}\n--- stdout ---\n${stdout.slice(0, 400)}`));
      }
    });
  });
}

const byId = (results) => Object.fromEntries(results.map((r) => [r.id, r.status]));

before(async () => {
  certs = makeCerts();
  await startApp('insecure-app');
  await startApp('secure-app');
});

after(() => {
  for (const p of procs) p.kill();
});

test('runtime: insecure sample app fails the expected checks', async () => {
  const s = byId(await scan('insecure-app'));
  assert.equal(s['http-redirect'], 'fail');
  assert.equal(s['hsts'], 'warn');
  assert.equal(s['tls-cert'], 'pass');
  if (s['tls-1.0'] !== 'skip') assert.equal(s['tls-1.0'], 'fail');
  assert.equal(s['cache-control:/dashboard'], 'fail');
  assert.equal(s['method:TRACE'], 'fail');
  // TRACK is not tested here: Node's HTTP parser rejects it with a 400 before the app sees it.
  assert.equal(s['token-endpoint:/oauth/callback'], 'fail');
  assert.equal(s['cache-control:/oauth/callback'], 'fail');
  assert.equal(s['open-redirect:next'], 'fail');
  assert.equal(s['cookie:sid'], 'fail');
  assert.equal(s['disclosure'], 'warn');
  assert.equal(s['security-headers'], 'warn');
});

test('runtime: secure sample app passes every check', async () => {
  const results = await scan('secure-app');
  const s = byId(results);
  for (const id of ['http-redirect', 'hsts', 'tls-1.0', 'tls-1.1', 'tls-modern', 'tls-cert', 'cache-control:/dashboard', 'method:TRACE', 'method:TRACK',
    'token-endpoint:/oauth/callback', 'cache-control:/oauth/callback', 'open-redirect', 'cookie:sid', 'security-headers']) {
    assert.equal(s[id], 'pass', id);
  }
  assert.deepEqual(results.filter((r) => r.status === 'fail'), []);
});

test('source: insecure sample app is flagged, secure sample app is clean', () => {
  const bad = byId(scanSource(path.join(root, 'examples', 'insecure-app')).results);
  for (const id of ['src:log-token', 'src:inline-key', 'src:static-state', 'src:token-encryption', 'src:realm-encryption', 'src:token-to-browser']) {
    assert.equal(bad[id], 'fail', id);
  }
  assert.equal(bad['src:sql-concat'], 'warn');

  const good = scanSource(path.join(root, 'examples', 'secure-app')).results;
  const g = byId(good);
  assert.equal(g['src:token-encryption'], 'pass');
  assert.equal(g['src:state-check'], 'pass');
  assert.equal(g['src:csrf-lib'], 'pass');
  assert.deepEqual(good.filter((r) => r.status === 'fail' || r.status === 'warn').map((r) => r.id), []);
});
