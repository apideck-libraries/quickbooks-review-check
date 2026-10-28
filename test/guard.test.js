import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPublicIp, validateTarget, TargetError, assertPublicHost } from '../src/guard.js';

test('isPublicIp blocks private, loopback, metadata and mapped addresses', () => {
  for (const ip of ['10.1.2.3', '127.0.0.1', '169.254.169.254', '172.20.0.1', '192.168.1.1', '100.64.0.1', '0.0.0.0', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1']) {
    assert.equal(isPublicIp(ip), false, ip);
  }
  for (const ip of ['93.184.216.34', '1.1.1.1', '2606:4700:4700::1111']) assert.equal(isPublicIp(ip), true, ip);
});

test('validateTarget rejects internal targets and odd ports', () => {
  for (const u of ['http://localhost', 'https://127.0.0.1', 'https://[::1]/', 'https://intranet', 'https://db.internal', 'https://a.com:8443', 'ftp://a.com', 'https://u:p@a.com']) {
    assert.throws(() => validateTarget(u), TargetError, u);
  }
  assert.equal(validateTarget('app.example.com').href, 'https://app.example.com/');
});

test('assertPublicHost rejects names resolving to loopback', async () => {
  await assert.rejects(assertPublicHost('localhost'), TargetError);
});
