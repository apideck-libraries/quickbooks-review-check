export const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.nuxt', '.output', '.vercel', 'vendor', 'coverage', 'out', 'target', '__pycache__', '.venv', 'venv', 'bin', 'obj', '.turbo', '.cache']);
export const EXTS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts', '.vue', '.svelte', '.py', '.rb', '.php', '.java', '.kt', '.cs', '.go', '.ejs', '.erb', '.hbs', '.html']);
const TEST_FILE = /(^|[\\/])(test|tests|__tests__|__mocks__|spec|fixtures?|examples?)[\\/]|\.(test|spec)\.[a-z]+$/i;
export const MAX_BYTES = 1024 * 1024;

const TOKEN_WORDS = String.raw`(access_?token|refresh_?token|accessToken|refreshToken|realm_?id|realmId|client_?secret|clientSecret|authResponse|getToken\(\)|getJson\(\)|bearer)`;

// Line rules. `status` is the result status when the rule matches.
export const LINE_RULES = [
  {
    id: 'log-token', requirement: 'patching-logging', status: 'fail',
    title: 'OAuth tokens or realmId written to logs',
    re: new RegExp(String.raw`(console\.(log|info|debug|warn|error|trace)|\blogger\.\w+|\blog\.(info|debug|warn|error|trace)|\bprint(ln|f)?\s*\(|\bputs\b|\blogging\.\w+|Log\.(d|i|e|w)\(|\berror_log\(|fmt\.Print)[^\n]*\b${TOKEN_WORDS}`, 'i'),
    fix: 'Never log tokens, realmId, or QuickBooks payloads. Log a token fingerprint (last 4 chars) or a request id instead.',
  },
  {
    id: 'inline-key', requirement: 'key-storage', status: 'fail',
    title: 'Encryption key hardcoded in source',
    re: /\b(encrypt(ion)?_?key|aes_?key|cipher_?key|crypto_?key|token_?key|secret_?key)\b\s*[:=]\s*['"`][^'"`\s]{12,}['"`]|createCipheriv\(\s*['"`][^'"`]+['"`]\s*,\s*['"`]/i,
    fix: 'Load the AES key from a separate config file or secret manager (env var, AWS KMS, Vault) — Intuit requires it not be inline.',
  },
  {
    id: 'inline-client-secret', requirement: 'token-exposure', status: 'fail',
    title: 'Intuit client secret hardcoded in source',
    re: /\bclient_?secret\b['"]?\s*[:=]\s*['"`][A-Za-z0-9]{30,}['"`]/i,
    fix: 'Move the client secret to environment/secret storage and rotate it in the Intuit developer portal.',
  },
  {
    id: 'tls-verify-off', requirement: 'https-everywhere', status: 'fail',
    title: 'TLS certificate verification disabled',
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|ServerCertificateValidationCallback\s*=.*=>\s*true/,
    fix: 'Never disable certificate validation; tokens can be intercepted by a MITM.',
  },
  {
    id: 'token-to-browser', requirement: 'token-exposure', status: 'fail',
    title: 'OAuth tokens sent to or stored in the browser',
    re: new RegExp(String.raw`(localStorage|sessionStorage)\.setItem\([^)]*(token|realm)|res\.(json|send|end|write)\([^)]*\b(refresh_?token|refreshToken|authResponse|getJson\(\)|oauthClient\.getToken\(\)|getToken\(\))|jsonify\([^)]*refresh_token|[?&](access_token|refresh_token)=\$\{|[?&](access_token|refresh_token)=['"]?\s*\+`, 'i'),
    fix: 'Keep Intuit tokens server-side only. The browser should hold an opaque session cookie, never access/refresh tokens or realmId.',
  },
  {
    id: 'weak-cipher', requirement: 'token-encryption', status: 'warn',
    title: 'Weak or deprecated encryption mode',
    re: /createCipher\(|createDecipher\(|aes-\d+-ecb|AES\.MODE_ECB|AES\/ECB|\brc4\b|des-cbc['"]|DES\/CBC|Cipher\.getInstance\(\s*"AES"\s*\)/i,
    fix: 'Use AES-256-GCM (or AES-256-CBC + HMAC) with a random IV per record via createCipheriv / AESGCM.',
  },
  {
    id: 'cookie-flag-off', requirement: 'cookie-flags', status: 'warn',
    title: 'Cookie configured without Secure/HttpOnly',
    re: /\b(httpOnly|http_only|httponly)\s*[:=]\s*(false|False)|\bsecure\s*:\s*false\b|SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False/,
    fix: 'Set secure: true and httpOnly: true for session cookies in every non-local environment.',
  },
  {
    id: 'sql-concat', requirement: 'injection', status: 'warn',
    title: 'SQL built with string interpolation',
    re: /(\.query|\.execute|\.exec|\.raw|\$queryRawUnsafe|\$executeRawUnsafe|knex\.raw|sequelize\.query|db\.run|cursor\.execute)\s*\(\s*(`[^`]*\$\{|['"][^'"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*\+|f['"][^'"]*\b(SELECT|INSERT|UPDATE|DELETE)\b|['"][^'"]*%s[^'"]*['"]\s*%)/i,
    fix: 'Use parameterized queries / prepared statements.',
  },
  {
    id: 'qbo-query-concat', requirement: 'injection', status: 'warn',
    title: 'QuickBooks query built with string interpolation',
    re: /\bselect\s+\*?\s*[\w,\s]*\s+from\s+(Invoice|Customer|Vendor|Bill|Item|Account|Payment|Estimate)\b[^'"`]*(\$\{|['"`]\s*\+)/i,
    fix: 'Escape single quotes in values interpolated into QuickBooks query language (e.g. DisplayName = \'O\\\'Brien\').',
  },
  {
    id: 'xss-sink', requirement: 'xss', status: 'warn',
    title: 'Unescaped HTML output sink',
    re: /dangerouslySetInnerHTML|\.innerHTML\s*=(?!=)|\bv-html=|\{\{\{|<%-|\|\s*safe\b|\.html_safe\b|\bmark_safe\(|@Html\.Raw\(|\{@html\s/,
    fix: 'Make sure QuickBooks data (customer names, memos) and user input are escaped or sanitized (DOMPurify) before rendering.',
  },
  {
    id: 'xxe', requirement: 'injection', status: 'warn',
    title: 'XML parser may resolve external entities',
    re: /noent\s*:\s*true|resolve_entities\s*=\s*True|XmlUrlResolver\(|DtdProcessing\.Parse|LIBXML_NOENT|setExpandEntityReferences\(\s*true/,
    fix: 'Disable DTDs/external entity resolution in XML parsers.',
  },
];

const INTUIT_REF = /intuit-oauth|node-quickbooks|quickbooks|oauth\.platform\.intuit\.com|appcenter\.intuit\.com|intuitlib|IntuitAuthorization|realmId|realm_id|com\.intuit\.oauth2/i;
const AUTHORIZE_REF = /authorizeUri|authorize_url|get_authorization_url|appcenter\.intuit\.com\/connect\/oauth2|OAuth2PlatformClient|getAuthorizationURL/i;
const STATIC_STATE = /\bstate(_token)?\s*[:=]\s*['"`]([A-Za-z0-9_-]{2,40})['"`]/;
const STATE_CHECK = /\bstate\b[^\n]{0,80}(!==|===|!=|==|\bnot in\b|\bequals\()|(req\.query|request\.args|params|searchParams|query)\W{0,3}\.?(get\(\s*['"])?state\b[^\n]{0,120}(session|cookie|stored|expected)|validateState|verifyState|check_state|state_matches|timingSafeEqual/i;
const CSRF_LIB = /\bcsurf\b|csrf-csrf|\blusca\b|@fastify\/csrf|@edge-csrf|CsrfViewMiddleware|protect_from_forgery|csrf_token|ValidateAntiForgeryToken|next-csrf|csrf\(\)|tiny-csrf|SameSite=Strict|sameSite\s*:\s*['"](strict|lax)/i;
const PERSIST_TOKEN = /\b(refresh_?token|refreshToken)\b[^\n]{0,160}\b(save|insert|update|upsert|create|set|put|write|store|persist|hset|setex|INSERT|UPDATE)\b|\b(save|insert|update|upsert|create|store|persist|hset|setex)\w*\s*\([^\n]{0,160}\b(refresh_?token|refreshToken)\b|\b(refresh_?token|refreshToken)\s*[:=]\s*(token|authResponse|response|tokens|json|data|oauth)/i;
const PERSIST_REALM = /\b(realm_?id|realmId)\b[^\n]{0,120}\b(save|insert|update|upsert|create|store|persist|INSERT|UPDATE)\b|\b(realm_?id|realmId)\s*:\s*(req|request|params|query|token|authResponse)\b/i;
const ENCRYPT_EVIDENCE = /createCipheriv\(\s*['"`]?(aes|des-ede3)|createCipheriv\(|crypto\.subtle\.encrypt|['"]AES-GCM['"]|AES\.new\(|AESGCM\(|\bFernet\(|Cipher\.getInstance\(\s*"(AES|DESede)|openssl_encrypt\(|ActiveRecord::Encryption|\bencrypts\s+:|attr_encrypted|lockbox|TripleDES|des-ede3|@47ng\/cloak|prisma-field-encryption|mongoose-(field-)?encryption|crypto-js[^\n]*AES|CryptoJS\.AES|kms[\w.]*\.?encrypt|EncryptCommand|secretbox|AesGcm|Aes\.Create\(|\bencrypt(Token|RefreshToken|Secret|Field|Value)?\s*\(/i;
const THIRD_PARTY = [
  { re: /['"](openai|@anthropic-ai\/sdk|@google\/generative-ai|@ai-sdk\/[\w-]+|ai|langchain|@langchain\/[\w-]+|cohere-ai)['"]|^\s*(import|from)\s+(openai|anthropic|langchain)\b/m, name: 'LLM provider' },
  { re: /['"](@segment\/analytics-node|analytics-node|mixpanel|posthog-node|posthog-js|amplitude|@amplitude\/[\w-]+|@hubspot\/api-client|intercom-client|heap-api)['"]/, name: 'analytics / CRM SDK' },
  { re: /['"](@sentry\/[\w-]+|@datadog\/[\w-]+|dd-trace|newrelic|@logtail\/[\w-]+|logrocket|@bugsnag\/[\w-]+|rollbar)['"]|^\s*import\s+sentry_sdk/m, name: 'error/APM SDK' },
];
const APIDECK_REF = /@apideck\/[\w-]+|unify\.apideck\.com|vault\.apideck\.com|x-apideck-consumer-id|apideck-unify|from apideck_unify|apideck\.vault/i;
const QBO_DATA = /\b(Invoice|Customer|Vendor|Bill|JournalEntry|Payment|SalesReceipt|CompanyInfo|getInvoice|findCustomers|findInvoices|QueryResponse)\b/;

// Decide whether a file (by basename) is scanned as code, as a local env file, or skipped.
export function classifyFile(name) {
  if (/^\.env(\.|$)/.test(name)) return /example|sample|template|dist/.test(name) ? null : 'env';
  if (/\.min\.js$/.test(name)) return null;
  const dot = name.lastIndexOf('.');
  return dot > 0 && EXTS.has(name.slice(dot).toLowerCase()) ? 'code' : null;
}

export function isSkippedDir(name) {
  return SKIP_DIRS.has(name) || name.startsWith('.');
}

const loc = (file, line, text) => ({ file, line, snippet: text.trim().slice(0, 160) });

// files: [{ rel, text, kind: 'code' | 'env' }] — pure, so it runs in Node and in the browser.
export function scanFiles(files, { includeTests = false } = {}) {
  const hits = new Map(LINE_RULES.map((rule) => [rule.id, []]));
  const evidence = { apideck: [], intuit: [], authorize: [], staticState: [], stateCheck: [], csrfLib: [], persistToken: [], persistRealm: [], encrypt: [], thirdParty: new Map(), envSecrets: [] };
  let scanned = 0;

  for (const f of files) {
    if (f.text.length > MAX_BYTES) continue;
    const { text } = f;
    scanned++;

    if (f.kind === 'env') {
      text.split('\n').forEach((l, i) => {
        if (/^\s*(\w*(CLIENT_SECRET|ENCRYPTION_KEY|AES_KEY|REFRESH_TOKEN)\w*)\s*=\s*\S{8,}/i.test(l)) evidence.envSecrets.push(loc(f.rel, i + 1, l.replace(/=.*/, '=***')));
      });
      continue;
    }
    const isTest = TEST_FILE.test(f.rel);
    if (isTest && !includeTests) continue;

    const lines = text.split('\n');
    const fileIntuit = INTUIT_REF.test(text);
    const fileAuthorize = AUTHORIZE_REF.test(text);
    const fileQbo = fileIntuit && QBO_DATA.test(text);

    lines.forEach((line, i) => {
      if (line.length > 2000) return;
      const n = i + 1;
      for (const rule of LINE_RULES) if (rule.re.test(line)) hits.get(rule.id).push(loc(f.rel, n, line));
      if (APIDECK_REF.test(line)) evidence.apideck.push(loc(f.rel, n, line));
      if (fileIntuit && INTUIT_REF.test(line)) evidence.intuit.push(loc(f.rel, n, line));
      if (AUTHORIZE_REF.test(line)) evidence.authorize.push(loc(f.rel, n, line));
      if (fileAuthorize) {
        const m = STATIC_STATE.exec(line);
        if (m && !/^(state|query|params|body)$/i.test(m[2])) evidence.staticState.push(loc(f.rel, n, line));
      }
      if (STATE_CHECK.test(line)) evidence.stateCheck.push(loc(f.rel, n, line));
      if (CSRF_LIB.test(line)) evidence.csrfLib.push(loc(f.rel, n, line));
      if (PERSIST_TOKEN.test(line)) evidence.persistToken.push(loc(f.rel, n, line));
      if (PERSIST_REALM.test(line)) evidence.persistRealm.push(loc(f.rel, n, line));
      if (ENCRYPT_EVIDENCE.test(line)) evidence.encrypt.push(loc(f.rel, n, line));
    });

    if (fileQbo) for (const tp of THIRD_PARTY) if (tp.re.test(text)) {
      if (!evidence.thirdParty.has(tp.name)) evidence.thirdParty.set(tp.name, []);
      evidence.thirdParty.get(tp.name).push(loc(f.rel, 1, `imports ${tp.name}`));
    }
  }

  return { scanned, results: buildResults(hits, evidence) };
}

const res = (id, requirement, status, title, detail, extra = {}) => ({ id, requirement, status, title, detail, ...extra });

function buildResults(hits, ev) {
  const out = [];
  if (!ev.intuit.length) {
    out.push(res('src:intuit', 'token-encryption', 'warn', 'No QuickBooks integration code detected', 'Could not find intuit-oauth, node-quickbooks, realmId or Intuit OAuth URLs. OAuth-specific checks below are less reliable. (If you connect to QuickBooks through Apideck Vault, Intuit tokens are stored and encrypted by Apideck, not your app.)'));
  }

  for (const rule of LINE_RULES) {
    const h = hits.get(rule.id);
    if (h.length) out.push(res(`src:${rule.id}`, rule.requirement, rule.status, rule.title, `${h.length} occurrence${h.length > 1 ? 's' : ''}.`, { locations: h.slice(0, 15), fix: rule.fix }));
  }

  // OAuth CSRF (state parameter)
  if (ev.staticState.length) {
    out.push(res('src:static-state', 'csrf', 'fail', 'OAuth state parameter is a constant', 'The authorize URL uses a hardcoded `state` (Intuit\'s sample code ships `testState`). That disables CSRF protection on the connect flow.',
      { locations: ev.staticState.slice(0, 10), fix: 'Generate a random state per request (crypto.randomBytes(32)), store it in the session, and compare it in the callback before exchanging the code.' }));
  } else if (ev.authorize.length && !ev.stateCheck.length) {
    out.push(res('src:state-check', 'csrf', 'warn', 'No OAuth state validation found', 'Found an Intuit authorize URL but no code comparing the returned `state` to a stored value.', { locations: ev.authorize.slice(0, 5), fix: 'Verify `state` in the callback with a constant-time compare before calling createToken.' }));
  } else if (ev.authorize.length) {
    out.push(res('src:state-check', 'csrf', 'pass', 'OAuth state appears to be validated', 'Found state comparison logic.', { locations: ev.stateCheck.slice(0, 3) }));
  }
  if (ev.csrfLib.length) out.push(res('src:csrf-lib', 'csrf', 'pass', 'CSRF protection in place', 'Found CSRF middleware or SameSite cookie configuration.', { locations: ev.csrfLib.slice(0, 3) }));
  else out.push(res('src:csrf-lib', 'csrf', 'warn', 'No CSRF middleware detected', 'No CSRF library or SameSite cookie config found. Intuit\'s pen test checks state-changing forms and endpoints.', { fix: 'Add CSRF tokens (csrf-csrf, Django/Rails built-ins) or SameSite=Lax/Strict session cookies plus origin checks.' }));

  // Token encryption at rest
  const persisted = ev.persistToken.length > 0;
  if (persisted && !ev.encrypt.length) {
    out.push(res('src:token-encryption', 'token-encryption', 'fail', 'Refresh token stored without encryption', 'Found code persisting the refresh token but no AES/3DES encryption anywhere in the codebase.',
      { locations: ev.persistToken.slice(0, 10), fix: 'Encrypt refresh token and realmId with AES-256-GCM before writing them (see README for a 20-line helper).' }));
  } else if (persisted) {
    out.push(res('src:token-encryption', 'token-encryption', 'pass', 'Encryption used near token storage', 'Found both token persistence and AES/3DES encryption. Confirm the refresh token *and* realmId pass through it before every write.',
      { locations: [...ev.persistToken.slice(0, 3), ...ev.encrypt.slice(0, 3)] }));
  } else if (ev.apideck.length && !ev.authorize.length) {
    out.push(res('src:token-encryption', 'token-encryption', 'pass', 'Intuit tokens held by Apideck Vault', 'This app connects to QuickBooks through Apideck and runs no Intuit OAuth flow of its own, so refresh tokens and realmId are stored and encrypted by Apideck. Make sure your Apideck API key stays server-side.', { locations: ev.apideck.slice(0, 2) }));
  } else if (ev.intuit.length) {
    out.push(res('src:token-encryption', 'token-encryption', 'warn', 'Could not locate refresh-token storage', 'Intuit code found, but no obvious write of the refresh token. If you persist it (you must, to stay connected), make sure it is AES-encrypted.'));
  }
  if (ev.persistRealm.length && !ev.encrypt.length) {
    out.push(res('src:realm-encryption', 'token-encryption', 'fail', 'realmId stored without encryption', 'Intuit requires realmId to be encrypted at rest along with the refresh token.', { locations: ev.persistRealm.slice(0, 5) }));
  }

  // Key storage
  if (!hits.get('inline-key').length && ev.encrypt.length) out.push(res('src:key-storage', 'key-storage', 'pass', 'No inline encryption key found', 'Encryption keys appear to be loaded from configuration.'));
  if (ev.envSecrets.length) out.push(res('src:env-secrets', 'key-storage', 'warn', 'Secrets present in local .env files', 'Make sure these files are git-ignored and never deployed to the client bundle.', { locations: ev.envSecrets.slice(0, 10) }));

  // Third-party data sharing
  for (const [name, locs] of ev.thirdParty) {
    out.push(res(`src:third-party:${name}`, 'no-third-party-access', 'warn', `QuickBooks data code also imports ${name}`, `Files that handle QuickBooks entities import a ${name}. Intuit prohibits sending customer QuickBooks data to third parties outside your app's function — verify payloads${name.startsWith('error') ? ' are scrubbed (e.g. Sentry beforeSend)' : ''}.`, { locations: locs.slice(0, 10) }));
  }
  return out;
}
