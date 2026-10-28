# Apideck QuickBooks Review Check

[![npm](https://img.shields.io/npm/v/@apideck/quickbooks-review-check)](https://www.npmjs.com/package/@apideck/quickbooks-review-check)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Free, open-source self-check for the Intuit QuickBooks Online app security review.** Run it before you submit, and on every deploy after you're listed, so Intuit's yearly re-review doesn't catch you out.

Try it in the browser at **[apideck.com/tools/quickbooks-review](https://www.apideck.com/tools/quickbooks-review)**, run it locally with `npx`, or add it to CI as a GitHub Action.

> **Disclaimer.** This is a self-assessment aid, not a certification, penetration test, security audit or legal/compliance advice. Passing these checks does not mean an app meets Intuit's requirements or will be approved. Always confirm requirements against Intuit's official developer documentation. Only run runtime checks against apps you own or are authorized to test. Provided "as is" under the MIT License, without warranty.
>
> Not affiliated with, endorsed by or sponsored by Intuit Inc. Intuit and QuickBooks are trademarks of Intuit Inc., used only to describe what the tool checks against.

## Contents

- [What it checks](#what-it-checks)
- [Quick start](#quick-start)
- [GitHub Action guide](#github-action-guide)
- [Reading the results](#reading-the-results)
- [CLI reference](#cli-reference)
- [Troubleshooting](#troubleshooting)
- [Fixing common findings](#fixing-common-findings)
- [Using Apideck?](#using-apideck)
- [Sample apps](#sample-apps)
- [Development](#development)

## What it checks

| | What it checks | How |
|---|---|---|
| **Runtime** | HTTPS enforcement, TLS 1.0/1.1/1.2/1.3, certificate, HSTS, `Cache-Control: no-store` (not `private`) on sensitive pages, TRACE/TRACK disabled, `Secure` + `HttpOnly` session cookies, the **302 rule** on your OAuth callback, open redirects, version-banner disclosure, browser security headers | Ordinary HTTP requests and TLS handshakes against your deployed app |
| **Source** | Refresh token **and realmId** encrypted at rest (AES/3DES), encryption key not inline, tokens or `authResponse` logged, tokens sent to the browser or `localStorage`, a hardcoded `state: 'testState'` (CSRF, from Intuit's sample code), missing state validation, CSRF middleware, TLS verification disabled, weak ciphers (ECB, `createCipher`), SQL and QuickBooks-query string interpolation, XSS sinks, XXE, QuickBooks data near LLM/analytics/APM SDKs | Pattern-based scan of your repo (JS/TS, Python, Ruby, PHP, Java, C#, Go). Nothing is uploaded. |

Every result maps to one of Intuit's review areas. Each report ends with a **sign-off checklist** for what no scanner can prove: patching, access control, a penetration test or DAST scan, and the QuickBooks data-usage rules.

## Quick start

**In the browser:** [apideck.com/tools/quickbooks-review](https://www.apideck.com/tools/quickbooks-review). Probe a deployed app, or pick a folder to scan in the browser, and download an auditor-style PDF report.

**From your terminal** (Node 20 or later, nothing to install):

```bash
npx @apideck/quickbooks-review-check \
  --url https://app.example.com \
  --callback /oauth/quickbooks/callback \
  --path /dashboard \
  --header "Cookie: session=…" \
  --source .
```

**In CI:** add `.github/workflows/quickbooks-review.yml`:

```yaml
name: QuickBooks review check
on:
  pull_request:
  schedule:
    - cron: '0 6 * * 1' # every Monday

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: apideck-libraries/quickbooks-review-check@v0
        with:
          url: https://app.example.com
          callback: /oauth/quickbooks/callback
```

The report appears in the workflow run's job summary.

## GitHub Action guide

### Inputs

| Input | Default | Description |
|---|---|---|
| `url` | | Base URL of the deployed app. Runs the runtime checks. Leave empty to only scan source. |
| `callback` | | Your OAuth redirect URI path, as registered with Intuit (e.g. `/oauth/quickbooks/callback`). Checks the 302 rule, caching and cookies on it. |
| `paths` | | Sensitive pages that must not be cached, one per line (e.g. `/dashboard`). |
| `headers` | | Extra request headers, one per line. Use it to send a session cookie so signed-in pages are checked. Always pass values from secrets. |
| `source` | `.` | Directory to scan. Set to `''` to skip the source scan. |
| `fail-on` | `fail` | When the step fails: `fail` (any failed check), `warn` (also on warnings) or `never`. |

### Outputs

| Output | Description |
|---|---|
| `report` | Path to the Markdown report |
| `report-json` | Path to the JSON report |
| `failed` | Number of failed checks |
| `warnings` | Number of warnings |
| `passed` | Number of passed checks |

The outputs are set even when the step fails, so later steps with `if: always()` can use them.

### Recipe: check every deployment

Run after each successful deploy (Vercel, Netlify, Render and others create GitHub deployments) against the URL that was just deployed:

```yaml
on: deployment_status

jobs:
  check:
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.deployment.sha }}
      - uses: apideck-libraries/quickbooks-review-check@v0
        with:
          url: ${{ github.event.deployment_status.environment_url }}
          callback: /oauth/quickbooks/callback
```

If preview deployments sit behind a login (for example Vercel Deployment Protection), point `url` at production instead, or pass the provider's bypass header through `headers`.

### Recipe: weekly drift check

Listed apps are reviewed again by Intuit. A weekly run catches a changed header or proxy setting long before that:

```yaml
on:
  schedule:
    - cron: '0 6 * * 1'
  workflow_dispatch:
```

### Recipe: source-only check on pull requests

No deployed URL needed. Catches a new `console.log(token)` or a hardcoded key before merge:

```yaml
on: pull_request

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: apideck-libraries/quickbooks-review-check@v0
        with:
          source: .
```

### Recipe: check signed-in pages

Without a session, sensitive pages usually redirect to your login page, and the cache check can't see them. Create a dedicated test account, copy its session cookie into a repository secret (Settings → Secrets and variables → Actions → `QBRC_SESSION_COOKIE`), then:

```yaml
      - uses: apideck-libraries/quickbooks-review-check@v0
        with:
          url: https://app.example.com
          callback: /oauth/quickbooks/callback
          paths: |
            /dashboard
            /settings/integrations
          headers: |
            Cookie: ${{ secrets.QBRC_SESSION_COOKIE }}
```

Use a test account with no real customer data, and rotate the cookie when it expires.

### Recipe: keep the report as an artifact

```yaml
      - id: qbo
        uses: apideck-libraries/quickbooks-review-check@v0
        with:
          url: https://app.example.com
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: quickbooks-review
          path: |
            ${{ steps.qbo.outputs.report }}
            ${{ steps.qbo.outputs.report-json }}
```

### Recipe: alert on failures without blocking

```yaml
      - id: qbo
        uses: apideck-libraries/quickbooks-review-check@v0
        with:
          url: https://app.example.com
          fail-on: never
      - if: steps.qbo.outputs.failed != '0'
        run: |
          curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"QuickBooks review check: ${{ steps.qbo.outputs.failed }} failed, ${{ steps.qbo.outputs.warnings }} warnings\"}" \
            "${{ secrets.SLACK_WEBHOOK_URL }}"
```

## Reading the results

Each check has one of five statuses:

| Status | Meaning |
|---|---|
| **Fail** | The control is missing or wrong. Expect Intuit to flag it. |
| **Warn** | Partly in place, or worth a look (source patterns can be false positives). |
| **Pass** | The control is in place. |
| **Info** | Context, such as the HTTP methods your server advertises. |
| **Skip** | Not checked, for example no cookies were seen or no callback was given. |

Results are grouped by Intuit's review areas: server and transport, attack vulnerabilities, cookies and sessions, OAuth token management, the token-endpoint redirect rule, and QuickBooks data usage. Each finding includes the evidence (the response header or `file:line`) and a fix.

The website version adds a PDF report with severities (High, Medium, Low), evidence, remediation and a sign-off page, which is useful to keep with your submission. Intuit requires critical, high and medium issues found in its review to be fixed before an app is published.

**Exit codes:** `0` all good (for the chosen `--fail-on`), `1` failures found, `2` usage error.

## CLI reference

```text
npx @apideck/quickbooks-review-check [options]

Runtime checks (probe your deployed app):
  --url <url>            Base URL of your deployed app
  --callback <path>      OAuth redirect URI path (checks the 302 rule, cache headers, cookies)
  --path <path>          Sensitive page to check for no-store caching (repeatable)
  --header "K: V"        Extra request header, e.g. a session cookie (repeatable)
  --timeout <ms>         Per-request timeout (default 10000)
  --http-port <port>     Port for the plain-HTTP redirect check (default 80; for local testing)

Source checks (static scan of your code):
  --source <dir>         Scan a repository for token-handling issues
  --include-tests        Also scan test/example files

Output:
  --markdown <file>      Write a Markdown report ("-" for stdout)
  --json <file>          Write a JSON report ("-" for stdout)
  --fail-on <level>      Exit 1 on: fail (default) | warn | never
  -q, --quiet            Don't print the console report
```

Examples:

```bash
# Source only, Markdown report to a file
npx @apideck/quickbooks-review-check --source . --markdown quickbooks-review.md

# Runtime only, JSON to stdout for scripting
npx @apideck/quickbooks-review-check --url https://app.example.com --json - --quiet | jq '.summary'

# Fail the build on warnings too
npx @apideck/quickbooks-review-check --source . --fail-on warn
```

## Troubleshooting

**"Callback /oauth/callback returned 404".** The `callback` path must match the Redirect URI registered in the Intuit developer portal, exactly.

**"Cache-Control not checked on /dashboard".** The page redirected, usually to your login. Pass a session cookie with `headers` / `--header`.

**The callback answers 4xx with JSON.** That passes. It means your app rejected the fake test code without rendering a page. A real authorization should still end in a 302, which you can confirm with a real connect flow.

**"TLS 1.0 not testable".** Your runner's OpenSSL can't offer TLS 1.0. The other TLS results are still valid.

**TRACE shows as refused.** A firewall or CDN blocking TRACE counts as disabled, which is what Intuit wants.

**The source scan flags something that's fine.** It matches patterns, so for example an `innerHTML` that only renders static text shows as a warning. Treat warnings as prompts to look.

**Internal or private URLs.** The hosted scanner on apideck.com only checks public hosts on ports 80/443. Run the CLI or the Action inside your network for anything else.

## Fixing common findings

The **[requirements guide](https://www.apideck.com/tools/quickbooks-review/checklist)** explains every check, with a command to verify it and fixes for Express, Next.js, nginx, Django and Rails. The fix Intuit reviewers ask about most is encrypting the refresh token and realmId with AES (preferred) or 3DES, with the key kept out of your code. In Node:

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

If your app connects to QuickBooks through [Apideck](https://www.apideck.com/accounting-api), you still register your own Intuit app and go through Intuit's review, but the OAuth redirect URI, token exchange, token storage and refresh run on Apideck Vault. Your app never holds the Intuit tokens, and the scanner recognizes this setup. You still own the runtime checks (HTTPS, cookies, cache headers) and the data-usage rules for your app, and this tool covers those.

## Sample apps

`examples/insecure-app` and `examples/secure-app` are two small QuickBooks apps (Node built-ins only) that the end-to-end test runs over real TLS:

- **insecure-app** does what many apps start with: Intuit's sample OAuth code with `state: 'testState'`, tokens logged and stored in plain text, an HTML callback page, TRACE echoed, TLS 1.0 accepted, `Cache-Control: private`, cookies without flags, an open redirect and plain HTTP. **Never deploy it.**
- **secure-app** fixes every one of those.

```bash
eval "$(node examples/certs.js)" && export TLS_KEY TLS_CERT NODE_EXTRA_CA_CERTS
node examples/insecure-app/server.js &   # https://localhost:8443, http://localhost:8080
node bin/quickbooks-review-check.js --url https://localhost:8443 --http-port 8080 --callback /oauth/callback --path /dashboard --source examples/insecure-app
```

`node examples/record.js <dir>` re-records both apps' scan results and source files for the website's "Try a sample" buttons.

## Development

```bash
npm test          # node:test, zero dependencies; includes the end-to-end test against both sample apps
node bin/quickbooks-review-check.js --source test/fixtures/insecure --fail-on never
```

Issues and pull requests for new checks are welcome.

MIT © Apideck
