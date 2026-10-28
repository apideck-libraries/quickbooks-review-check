import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { scanSource } from '../src/source.js';

const fixture = (n) => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));
const statusOf = (results) => Object.fromEntries(results.map((r) => [r.id, r.status]));

test('insecure Intuit sample-style app is flagged', () => {
  const s = statusOf(scanSource(fixture('insecure')).results);
  assert.equal(s['src:log-token'], 'fail');
  assert.equal(s['src:inline-key'], 'fail');
  assert.equal(s['src:static-state'], 'fail');
  assert.equal(s['src:token-encryption'], 'fail');
  assert.equal(s['src:realm-encryption'], 'fail');
  assert.equal(s['src:token-to-browser'], 'fail');
  assert.equal(s['src:sql-concat'], 'warn');
  assert.equal(s['src:cookie-flag-off'], 'warn');
});

test('secure app passes OAuth checks', () => {
  const results = scanSource(fixture('secure')).results;
  const s = statusOf(results);
  assert.equal(s['src:token-encryption'], 'pass');
  assert.equal(s['src:state-check'], 'pass');
  assert.equal(s['src:csrf-lib'], 'pass');
  assert.equal(s['src:key-storage'], 'pass');
  assert.deepEqual(results.filter((r) => r.status === 'fail'), []);
});
