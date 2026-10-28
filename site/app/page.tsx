import Link from 'next/link';
import { Scanner } from '@/components/Scanner';
import { Copy } from '@/components/Copy';
import { Attest } from '@/components/Attest';
import { REPO } from '@/lib/site';

const CLI = 'npx @apideck/quickbooks-review-check --url https://app.example.com --callback /oauth/callback --source .';

const YAML = `name: QuickBooks review check
on:
  deployment_status:
  schedule: [{ cron: '0 6 * * 1' }]
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
            Cookie: \${{ secrets.QBRC_SESSION_COOKIE }}
          source: .
          fail-on: fail   # or warn | never`;

function Yaml() {
  return (
    <pre>
      {YAML.split('\n').map((line, i) => {
        const m = /^(\s*-?\s*)([\w-]+:)(.*)$/.exec(line);
        if (!m) return <span key={i}>{line}{'\n'}</span>;
        const [, lead, key, rest] = m;
        const [val, comment] = rest.split('#');
        return (
          <span key={i}>
            {lead}<span className="k">{key}</span>
            {/'/.test(val) ? <span className="s">{val}</span> : val}
            {comment && <span className="c">#{comment}</span>}
            {'\n'}
          </span>
        );
      })}
    </pre>
  );
}

const faqs: [string, React.ReactNode][] = [
  ['If everything passes, will my app be approved?', 'No. This is a self-check, not a certification, penetration test or security audit. It catches common mechanical issues. Intuit decides on approval through its own review process, which this tool doesn’t replicate and has no part in.'],
  ['Is this affiliated with Intuit?', 'No. It’s an independent open-source project by Apideck. Intuit hasn’t endorsed or reviewed it. Our summary of the requirements is our reading of Intuit’s public documentation and may lag behind changes.'],
  ['What happens to my code when I scan it here?', 'Nothing leaves your browser. The source scan runs in this tab using the same rules as the CLI. You can disconnect from the network after the page loads and it still works.'],
  ['What does the live scan send to my app?', 'About 30 ordinary requests: a few GETs, a TRACE, TRACK and OPTIONS, a test call to your OAuth callback with fake parameters, and redirect probes with a harmless test URL. Plus four TLS handshakes. Only scan apps you own or are authorized to test.'],
  ['Why can’t I give the hosted scanner a session cookie?', 'Because we don’t want your session. To check signed-in pages, run the CLI or GitHub Action, where the cookie stays on your machine or in your CI secrets.'],
  ['Why might it flag code that’s fine?', <>The source scan uses patterns, so it reports things to review, like an <code>innerHTML</code> that only ever renders static text. Treat warnings as prompts to look, and failures as likely problems to confirm.</>],
  ['What does it cost?', 'Nothing. It’s MIT licensed and has no paid tier. Fork it, run it anywhere, and send pull requests for checks you want added.'],
  ['Do I need to keep checking after approval?', 'Listed apps can be reviewed again later, so run the GitHub Action on deploys and on a schedule. A changed header or a new logging line then shows up in CI first.'],
];

export default function Home() {
  return (
    <main>
      <section className="hero">
        <div className="wrap">
          <div className="hero-copy">
            <div>
              <p className="eyebrow">Free · open source · no sign-up</p>
              <h1 style={{ marginTop: 14 }}>Self-check your QuickBooks app <em>before</em> you submit it.</h1>
            </div>
            <div>
              <p className="lede">Probe your deployed app and scan your code for the mechanical issues that most often send QuickBooks Online apps back for another security-review cycle.</p>
              <ul className="facts">
                <li>Results in under a minute</li>
                <li>Code scanned in your browser</li>
                <li>CLI and GitHub Action</li>
              </ul>
            </div>
          </div>
          <Scanner />
        </div>
      </section>

      <section className="block" id="checks">
        <div className="wrap">
          <div className="sec-head">
            <h2>Two passes, one report</h2>
            <p>Some review items can be verified from outside by sending requests to your app. Others only show up in code. The tool does both and files every result under the review area it relates to.</p>
          </div>
          <div className="passes">
            <article className="pass-card">
              <div><p className="eyebrow">Pass 1 · runtime</p><h3>Probes your deployed app</h3></div>
              <p className="how">Ordinary HTTP requests and TLS handshakes, sent from our scanner, your machine or your CI runner.</p>
              <ul className="checks">
                <li><span>HTTP to HTTPS redirect, HSTS, trusted certificate</span></li>
                <li><span>TLS 1.0 and 1.1 refused, TLS 1.2+ negotiated, cipher strength</span></li>
                <li><span><code>Cache-Control: no-store</code> on sensitive pages, not <code>private</code></span></li>
                <li><span><code>TRACE</code> and <code>TRACK</code> disabled</span></li>
                <li><span><code>Secure</code> and <code>HttpOnly</code> on session cookies</span></li>
                <li><span>OAuth callback answers with a <code>302</code>, not an HTML page</span></li>
                <li><span>Open redirects on common parameters like <code>?next=</code></span></li>
                <li><span>Version banners and missing browser security headers</span></li>
              </ul>
            </article>
            <article className="pass-card">
              <div><p className="eyebrow">Pass 2 · source</p><h3>Scans your codebase</h3></div>
              <p className="how">Pattern-based scan of JS/TS, Python, Ruby, PHP, Java, C# and Go. It flags code to look at; it can’t prove code is safe.</p>
              <ul className="checks">
                <li><span>Refresh token <em>and</em> realmId stored without AES or 3DES</span></li>
                <li><span>Encryption keys or client secrets hardcoded in source</span></li>
                <li><span>Tokens or <code>authResponse</code> passed to loggers</span></li>
                <li><span>Tokens returned to the browser or put in <code>localStorage</code></span></li>
                <li><span>Constant OAuth <code>state</code> and missing state validation</span></li>
                <li><span>CSRF middleware, disabled TLS verification, ECB and deprecated ciphers</span></li>
                <li><span>SQL and QuickBooks-query string interpolation, XSS sinks, XXE</span></li>
                <li><span>QuickBooks data code that also imports LLM, analytics or APM SDKs</span></li>
              </ul>
            </article>
          </div>
        </div>
      </section>

      <section className="block">
        <div className="wrap">
          <div className="sec-head">
            <h2>Small mistakes that cost a review cycle</h2>
            <p>Most of these are one-line fixes. The hard part is knowing they matter before a reviewer points them out.</p>
          </div>
          <div className="catches">
            <div className="catch">
              <h3>Copying the sample’s state value</h3>
              <p>A fixed <code>state</code> turns off CSRF protection on the connect flow. Generate one per request and compare it in the callback.</p>
              <pre className="diff"><span className="rm">- authorizeUri({'{'} scope, state: &apos;testState&apos; {'}'})</span>{'\n'}<span className="ad">+ req.session.state = randomBytes(32).toString(&apos;hex&apos;)</span>{'\n'}<span className="ad">+ authorizeUri({'{'} scope, state: req.session.state {'}'})</span></pre>
            </div>
            <div className="catch">
              <h3>Using <code>private</code> as the cache header</h3>
              <p><code>private</code> still lets the browser cache the page. Sensitive pages need <code>no-store</code>.</p>
              <pre className="diff"><span className="rm">- Cache-Control: private, max-age=0</span>{'\n'}<span className="ad">+ Cache-Control: no-store, no-cache, must-revalidate</span></pre>
            </div>
            <div className="catch">
              <h3>Rendering a page on the OAuth callback</h3>
              <p>The callback URL carries the auth code and realmId. If it renders HTML, third-party scripts or images on that page can receive them in the Referer header.</p>
              <pre className="diff"><span className="rm">- res.send(&apos;&lt;h1&gt;Connected!&lt;/h1&gt;&apos;)</span>{'\n'}<span className="ad">+ res.redirect(302, &apos;/app/connected&apos;)</span></pre>
            </div>
            <div className="catch">
              <h3>Storing the refresh token as plain text</h3>
              <p>Encrypt the refresh token and realmId before writing them, and load the key from configuration, not from code.</p>
              <pre className="diff"><span className="rm">- db.save({'{'} refreshToken: token.refresh_token {'}'})</span>{'\n'}<span className="ad">+ db.save({'{'} refreshToken: encrypt(token.refresh_token) {'}'})</span>{'\n'}<span className="ad">+ {'// key: process.env.TOKEN_ENCRYPTION_KEY (AES-256-GCM)'}</span></pre>
            </div>
          </div>
        </div>
      </section>

      <section className="block" id="coverage">
        <div className="wrap">
          <div className="sec-head">
            <h2>What’s automated, and what isn’t</h2>
            <p>Some requirements are about policy and process, and no scanner can confirm them. Those go on a sign-off checklist at the end of every report. The <Link href="/checklist">requirements guide</Link> covers each item in depth.</p>
          </div>
          <div className="map-wrap">
            <table className="map">
              <thead><tr><th>Review area</th><th>Coverage</th><th>What the tool looks at</th></tr></thead>
              <tbody>
                <tr><td><Link href="/checklist#transport">Server &amp; transport</Link></td><td><span className="chip auto">automated</span></td><td>HTTPS, TLS versions, cache headers, HTTP methods, version banners, token logging in code</td></tr>
                <tr><td><Link href="/checklist#cookies">Cookies &amp; sessions</Link></td><td><span className="chip auto">automated</span></td><td>Set-Cookie flags on probed responses; cookie settings in code</td></tr>
                <tr><td><Link href="/checklist#redirect">Token-endpoint redirects</Link></td><td><span className="chip auto">automated</span></td><td>How your OAuth callback answers a test request</td></tr>
                <tr><td><Link href="/checklist#oauth">OAuth token management</Link></td><td><span className="chip part">heuristic</span></td><td>Encryption near token storage, inline keys, tokens reaching the browser</td></tr>
                <tr><td><Link href="/checklist#attacks">Attack vulnerabilities</Link></td><td><span className="chip part">heuristic</span></td><td>OAuth state, CSRF middleware, open redirects, injection and XSS patterns. Pair it with a DAST scan.</td></tr>
                <tr><td><Link href="/checklist#data">QuickBooks data usage</Link></td><td><span className="chip man">sign-off</span></td><td>Flags third-party SDKs near QuickBooks data; the rest is your attestation</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="block" id="ci">
        <div className="wrap ci">
          <div>
            <h2>Run it on every deploy</h2>
            <p className="muted" style={{ marginTop: 16, maxWidth: '52ch' }}>The CLI and GitHub Action run the same checks, plus signed-in pages using a session cookie that never leaves your infrastructure.</p>
            <div className="cmd"><code>{CLI}</code><Copy text={CLI} /></div>
            <div className="steps">
              <div><b>1</b><div><h3>Add the workflow</h3><p>Drop the YAML into <code>.github/workflows/</code>.</p></div></div>
              <div><b>2</b><div><h3>Give it a session</h3><p>Store a test-account cookie as a repository secret so it checks signed-in pages.</p></div></div>
              <div><b>3</b><div><h3>Read the job summary</h3><p>Results and the sign-off checklist appear on every run. Choose whether warnings fail the build.</p></div></div>
            </div>
          </div>
          <div className="code">
            <Copy text={YAML} />
            <Yaml />
          </div>
        </div>
      </section>

      <section className="block">
        <div className="wrap signoff">
          <div>
            <h2>The part you sign off yourself</h2>
            <p className="muted" style={{ marginTop: 16, maxWidth: '46ch' }}>Every report ends with this list. Tick items off here as you go; your ticks are saved only in this browser.</p>
          </div>
          <Attest />
        </div>
      </section>

      <section className="block">
        <div className="wrap">
          <div className="vault">
            <div>
              <p className="eyebrow">Connecting through Apideck?</p>
              <h2>Let Apideck hold the QuickBooks tokens</h2>
              <p>With Apideck Vault, Intuit OAuth tokens are stored and refreshed by Apideck instead of in your database. The scanner recognizes this setup. Your app still owns its runtime configuration and how it uses QuickBooks data, and the tool checks those either way.</p>
              <a className="btn" href="https://www.apideck.com/accounting-api">Explore the Accounting API</a>
            </div>
            <ul>
              <li>One integration for QuickBooks and other accounting platforms</li>
              <li>Token storage and refresh handled by Vault</li>
              <li>Ask our team for Apideck’s security documentation for your own review</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="block" id="faq" style={{ borderBottom: 0 }}>
        <div className="wrap">
          <div className="sec-head"><h2>Questions</h2><p>For the exact, current requirements, always go to Intuit’s own developer documentation. Found a bug or a missing check? <a href={`${REPO}/issues`}>Open an issue</a>.</p></div>
          <div className="faq">
            {[0, 1].map((col) => (
              <div key={col}>
                {faqs.filter((_, i) => i % 2 === col).map(([q, a], i) => (
                  <details key={q} open={col === 0 && i === 0}><summary>{q}</summary><p>{a}</p></details>
                ))}
              </div>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
