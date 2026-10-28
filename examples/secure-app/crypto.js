// AES-256-GCM for refresh tokens and realmIds. The key comes from configuration, never from code.
import crypto from 'node:crypto';

const key = () => Buffer.from(process.env.TOKEN_ENCRYPTION_KEY || '', 'base64');

export function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const data = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), data]).toString('base64');
}

export function decrypt(blob) {
  const buf = Buffer.from(blob, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key(), buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}
