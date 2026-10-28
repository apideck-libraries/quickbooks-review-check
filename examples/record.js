// Records real scanner output for both sample apps, for the website's "Try a sample" buttons.
// Usage: node examples/record.js <out-dir>
// Writes <app>.runtime.json (a recorded live scan) and <app>.source.json (the app's files, which the
// website scans in the browser).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeCerts } from './certs.js';
import { runRuntime } from '../src/runtime.js';
import { classifyFile } from '../src/scan-core.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(process.argv[2] || path.join(here, 'recorded'));
const APPS = { 'insecure-app': 'insecure-sample.example', 'secure-app': 'secure-sample.example' };

if (!process.env.NODE_EXTRA_CA_CERTS) {
  // The CA must be trusted at startup, so re-run this script with it set.
  const certs = makeCerts();
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), out], {
    env: { ...process.env, NODE_EXTRA_CA_CERTS: certs.ca, TLS_KEY: certs.key, TLS_CERT: certs.cert },
    stdio: 'inherit',
  });
  child.on('exit', (code) => process.exit(code ?? 1));
} else {
  fs.mkdirSync(out, { recursive: true });
  const freePort = () =>
    new Promise((resolve) => {
      const s = net.createServer().listen(0, () => {
        const { port } = s.address();
        s.close(() => resolve(port));
      });
    });

  for (const [app, displayHost] of Object.entries(APPS)) {
    const [httpsPort, httpPort] = [await freePort(), await freePort()];
    const server = spawn(process.execPath, [path.join(here, app, 'server.js')], {
      env: { ...process.env, HTTPS_PORT: String(httpsPort), HTTP_PORT: String(httpPort) },
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    await new Promise((resolve) => {
      let buf = '';
      server.stdout.on('data', (d) => {
        buf += d;
        if (buf.includes('https://') && buf.includes('http://')) resolve();
      });
    });
    const results = await runRuntime({
      url: `https://localhost:${httpsPort}`,
      httpPort,
      callback: '/oauth/callback',
      paths: ['/dashboard'],
    });
    server.kill();
    // Show a readable host instead of the throwaway local ports.
    const text = JSON.stringify(results, null, 1)
      .replaceAll(`https://localhost:${httpsPort}`, `https://${displayHost}`)
      .replaceAll(`http://localhost:${httpPort}`, `http://${displayHost}`);
    fs.writeFileSync(path.join(out, `${app}.runtime.json`), `${text}\n`);

    const files = fs
      .readdirSync(path.join(here, app))
      .filter((name) => classifyFile(name))
      .map((name) => ({ rel: name, kind: classifyFile(name), text: fs.readFileSync(path.join(here, app, name), 'utf8') }));
    fs.writeFileSync(path.join(out, `${app}.source.json`), `${JSON.stringify(files, null, 1)}\n`);
    console.log(`recorded ${app}: ${results.length} runtime results, ${files.length} source files`);
  }
}
