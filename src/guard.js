import dns from 'node:dns';
import net from 'node:net';

// SSRF guard for running runtime checks as a hosted service: only public hosts on standard ports,
// and every connection resolves through a lookup that re-checks the IP (defeats DNS rebinding).

const V4_BLOCKED = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

const v4ToInt = (ip) => ip.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;

export function isPublicIp(ip) {
  if (net.isIPv4(ip)) {
    const n = v4ToInt(ip);
    return !V4_BLOCKED.some(([base, bits]) => (n >>> (32 - bits)) === (v4ToInt(base) >>> (32 - bits)));
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
    if (mapped) return isPublicIp(mapped[1]);
    if (lower === '::' || lower === '::1') return false;
    // fc00::/7 unique-local, fe80::/10 link-local, ff00::/8 multicast, 2001:db8::/32 docs, 64:ff9b::/96 NAT64
    return !/^(f[cd]|fe[89ab]|ff|2001:db8|64:ff9b)/.test(lower);
  }
  return false;
}

export class TargetError extends Error {}

export function validateTarget(raw) {
  let u;
  try {
    u = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    throw new TargetError('Enter a valid URL, like https://app.example.com');
  }
  if (!['http:', 'https:'].includes(u.protocol)) throw new TargetError('Only http and https URLs can be checked.');
  if (u.username || u.password) throw new TargetError('Remove credentials from the URL.');
  if (u.port && !['80', '443'].includes(u.port)) throw new TargetError('The hosted scanner only checks standard ports (80/443). Use the CLI for other ports.');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host) && !isPublicIp(host)) throw new TargetError('Private and reserved IP addresses cannot be scanned.');
  if (/^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.lan|.*\.home\.arpa)$/i.test(host) || !host.includes('.')) {
    throw new TargetError('Internal hostnames cannot be scanned. Use the CLI inside your network instead.');
  }
  u.hash = '';
  return u;
}

// dns.lookup-compatible function that refuses non-public answers.
export function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const bad = addresses.find((a) => !isPublicIp(a.address));
    if (bad || !addresses.length) {
      const e = new Error(`${hostname} resolves to a non-public address`);
      e.code = 'EBLOCKED';
      return callback(e);
    }
    if (options.all) return callback(null, addresses);
    callback(null, addresses[0].address, addresses[0].family);
  });
}

export function assertPublicHost(hostname) {
  return new Promise((resolve, reject) => {
    safeLookup(hostname, { all: true }, (err, addrs) => (err ? reject(new TargetError(err.code === 'EBLOCKED' ? 'That host resolves to a private address and cannot be scanned.' : `Could not resolve ${hostname}.`)) : resolve(addrs)));
  });
}
