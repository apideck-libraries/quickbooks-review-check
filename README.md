# quickbooks-review-check

**Free, open-source self-check for the Intuit QuickBooks Online app security review.** Run it before you submit, and on every deploy after you're listed, so the annual re-review doesn't catch you out.

It does two kinds of checks, both free:

| | What it checks | How |
|---|---|---|
| **Runtime** | HTTPS enforcement, TLS 1.0/1.1/1.2/1.3, certificate, HSTS, `Cache-Control: no-store` (not `private`) on sensitive pages, TRACE/TRACK disabled, `Secure` + `HttpOnly` session cookies, the **302 rule** on your OAuth callback, open redirects, version-banner disclosure, browser security headers | Probes your deployed app from outside |
| **Source** | Refresh token **and realmId** encrypted at rest (AES/3DES), AES key not inline, tokens or `authResponse` logged, tokens sent to the browser / `localStorage`, hardcoded `state: 'testState'` (CSRF in Intuit's sample code), missing state validation, CSRF middleware, TLS verification disabled, weak ciphers (ECB, `createCipher`), SQL/QBO-query string interpolation, XSS sinks, XXE, QuickBooks data flowing into LLM/analytics/APM SDKs | Static scan of your repo (JS/TS, Python, Ruby, PHP, Java, C#, Go). No code leaves your machine. |

Every result maps to one of Intuit's review categories. Each report ends with a **manual attestation checklist** for the items no scanner can prove: patching, access control, DAST, and the data-usage rules.

> Not affiliated with or endorsed by Intuit. Passing these checks does not guarantee approval. It catches the common, mechanical reasons for rejection.

## Quick start

```bash
npx quickbooks-review-check \
  --url https://app.example.com \
  --callback /oauth/quickbooks/callback \
  --path /dashboard --path /settings/quickbooks \
  --header "Cookie: session=…" \
  --source .
```

- `--callback` is the Redirect URI you registered with Intuit. The tool calls it with a fake `code`, `state` and `realmId`, and checks that it answers with a `302`, not HTML.
- `--path` names sensitive pages that must send `no-store`. Pass a session cookie with `--header` so they're checked while signed in, not as a redirect to the login page.
- `--markdown report.md` and `--json report.json` write reports. `--fail-on warn|fail|never` controls the exit code.

## GitHub Action

```yaml
name: QuickBooks review check
on:
  deployment_status:
  schedule: [{ cron: '0 6 * * 1' }]   # weekly, catches drift before Intuit's annual re-review
  pull_request:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: apideck-libraries/quickbooks-review-check@v0
        with:
          url: https://app.example.com
          callback: /oauth/quickbooks/callback
          paths: |
            /dashboard
            /settings/quickbooks
          headers: |
            Cookie: ${{ secrets.QBRC_SESSION_COOKIE }}
          source: .
          fail-on: fail
```

The Markdown report is written to the job summary. To scan source only (e.g. on pull requests), omit `url`.

## Encrypting the refresh token (Node)

Intuit requires the refresh token and realmId to be encrypted with AES (preferred) or 3DES, with the key kept out of your code:

```js
import crypto from 'node:crypto';
const key = Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, 'base64'); // 32 bytes: `openssl rand -base64 32`

export function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), data]).toString('base64');
}

export function decrypt(blob) {
  const buf = Buffer.from(blob, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}
```

## Using Apideck?

If your app connects to QuickBooks through [Apideck Vault](https://www.apideck.com), Apideck stores and encrypts the Intuit OAuth tokens and realmId. Your app never holds them, so for the OAuth token-management section you point the reviewer to Apideck's security documentation instead of building token encryption yourself. You still own the runtime checks (HTTPS, cookies, cache headers) and the data-usage rules for your app, and this tool covers those.

## Development

```bash
npm test          # node:test, zero dependencies
node bin/quickbooks-review-check.js --source test/fixtures/insecure --fail-on never
```

MIT © Apideck
