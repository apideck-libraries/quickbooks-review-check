// Catalog of Intuit QuickBooks Online app security-review requirements.
// Each automated check references one of these ids so reports group by Intuit's categories.
// Source: Intuit Developer "Security requirements" for publishing an app (paraphrased).

export const CATEGORIES = {
  transport: 'Server & transport',
  attacks: 'Attack vulnerabilities',
  cookies: 'Cookies & sessions',
  oauth: 'OAuth token management',
  redirect: 'Token-endpoint redirect rule',
  data: 'QuickBooks data usage',
};

export const REQUIREMENTS = {
  'https-everywhere': {
    category: 'transport',
    title: 'HTTPS enforced on every page',
    text: 'All pages of the app must be served over HTTPS.',
  },
  'tls-version': {
    category: 'transport',
    title: 'TLS 1.1 minimum, TLS 1.2+ recommended',
    text: 'SSL must support TLS 1.1 or higher; TLS 1.2 with AES-256 and SHA-256 is recommended.',
  },
  'cache-control': {
    category: 'transport',
    title: 'Caching disabled on sensitive pages',
    text: 'Use Cache-Control no-cache and no-store (not private) on SSL and sensitive pages.',
  },
  'http-methods': {
    category: 'transport',
    title: 'TRACE and unused HTTP methods disabled',
    text: 'The web server must disable TRACE and other HTTP methods that are not used.',
  },
  'patching-logging': {
    category: 'transport',
    title: 'Patches current; no credential or QuickBooks data logging',
    text: 'OS, web server and app server patches must be current. Never log user credentials or QuickBooks data.',
  },
  csrf: {
    category: 'attacks',
    title: 'Cross-Site Request Forgery protection',
    text: 'State-changing requests (including the OAuth flow) must be protected against CSRF.',
  },
  xss: {
    category: 'attacks',
    title: 'Cross-Site Scripting (reflected & stored)',
    text: 'Validate input and encode output to prevent reflected and stored XSS.',
  },
  injection: {
    category: 'attacks',
    title: 'SQL and XML injection',
    text: 'Use parameterized queries and safe XML parsing.',
  },
  'auth-session': {
    category: 'attacks',
    title: 'Authentication, session management, access control',
    text: 'Authentication, session management and functional-level access control must be robust.',
  },
  'open-redirect': {
    category: 'attacks',
    title: 'Validated forwards and redirects',
    text: 'Redirect logic must be validated so it cannot be abused as an open redirect.',
  },
  'cookie-flags': {
    category: 'cookies',
    title: 'Secure and HttpOnly on session cookies',
    text: 'All session cookies must set the Secure and HttpOnly attributes.',
  },
  'token-exposure': {
    category: 'oauth',
    title: 'Tokens never exposed or shared',
    text: 'Intuit OAuth tokens and customer-identifying information must not be exposed in the app or shared with other parties.',
  },
  'token-encryption': {
    category: 'oauth',
    title: 'Refresh token and realmId encrypted at rest',
    text: 'Refresh token and realmId must be encrypted (AES preferred, or 3DES) and stored in persistent storage.',
  },
  'key-storage': {
    category: 'oauth',
    title: 'Encryption key kept in separate configuration',
    text: 'The AES key must be stored in a separate configuration file, not inline in code.',
  },
  'token-endpoint-302': {
    category: 'redirect',
    title: 'Token-bearing endpoints respond with 302, not HTML',
    text: 'Endpoints receiving tokens or sensitive data in URL parameters must not return HTML; they should 302 redirect to avoid Referer leaks.',
  },
  'no-third-party-access': {
    category: 'data',
    title: 'No third-party access to QuickBooks data',
    text: 'The app must not give third parties access to customer QuickBooks data, via APIs or any other means.',
  },
  'data-minimization': {
    category: 'data',
    title: 'Store QuickBooks data only for functional use',
    text: 'Do not export, save or store QuickBooks data for any purpose other than the functional use of the app.',
  },
};

// Items no scanner can prove. These are printed as an attestation checklist in every report.
export const MANUAL_CHECKS = [
  { id: 'patching-logging', prompt: 'OS, web server, runtime and dependencies are on current patch levels (e.g. `npm audit`, Dependabot, base image updates).' },
  { id: 'auth-session', prompt: 'Every route that reads or writes QuickBooks data enforces authentication and checks the user owns that realmId (no IDOR).' },
  { id: 'xss', prompt: 'A DAST scan (e.g. OWASP ZAP baseline) shows no reflected or stored XSS on authenticated pages.' },
  { id: 'injection', prompt: 'All database and XML access is parameterized; XML parsers have external entities disabled.' },
  { id: 'no-third-party-access', prompt: 'No QuickBooks data is sent to analytics, LLM, logging or other third-party services outside the app\'s stated function.' },
  { id: 'data-minimization', prompt: 'QuickBooks data is retained only as long as needed for the app\'s function, and deleted on disconnect.' },
  { id: 'token-exposure', prompt: 'Disconnect/revoke flow calls Intuit\'s revoke endpoint and deletes stored tokens.' },
];
