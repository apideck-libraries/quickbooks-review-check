// Creates a throwaway CA and a localhost certificate signed by it, so the sample apps serve
// real TLS that the scanner can verify (pass the CA via NODE_EXTRA_CA_CERTS).
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function makeCerts(dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qbrc-certs-'))) {
  const f = (name) => path.join(dir, name);
  const run = (...args) => execFileSync('openssl', args, { stdio: 'ignore' });
  run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=qbrc test CA', '-keyout', f('ca.key'), '-out', f('ca.crt'));
  run('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', f('server.key'), '-out', f('server.csr'));
  fs.writeFileSync(f('ext.cnf'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
  run('x509', '-req', '-in', f('server.csr'), '-CA', f('ca.crt'), '-CAkey', f('ca.key'), '-CAcreateserial', '-days', '2', '-extfile', f('ext.cnf'), '-out', f('server.crt'));
  return { dir, ca: f('ca.crt'), key: f('server.key'), cert: f('server.crt') };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const c = makeCerts(process.argv[2]);
  console.log(`TLS_KEY=${c.key}\nTLS_CERT=${c.cert}\nNODE_EXTRA_CA_CERTS=${c.ca}`);
}
