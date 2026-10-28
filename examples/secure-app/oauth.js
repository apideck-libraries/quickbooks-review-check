// OAuth handling that follows Intuit's security requirements.
import crypto from 'node:crypto';
import { encrypt } from './crypto.js';
import { saveCompany } from './db.js';

const NO_STORE = { 'cache-control': 'no-store, no-cache, must-revalidate', pragma: 'no-cache' };

let oauthClient;
async function client() {
  if (!oauthClient) {
    const { default: OAuthClient } = await import('intuit-oauth');
    oauthClient = new OAuthClient({
      clientId: process.env.QB_CLIENT_ID,
      clientSecret: process.env.QB_CLIENT_SECRET,
      environment: 'sandbox',
      redirectUri: process.env.QB_REDIRECT_URI,
    });
  }
  return oauthClient;
}

function redirect(res, location) {
  res.writeHead(302, { location, ...NO_STORE });
  res.end();
}

export async function handleConnect(req, res, session) {
  session.oauthState = crypto.randomBytes(32).toString('hex');
  const c = await client();
  redirect(res, c.authorizeUri({ scope: ['com.intuit.quickbooks.accounting'], state: session.oauthState }));
}

// Always answers with a redirect to a clean URL, on success and on failure, so the code and
// realmId in this URL never reach a rendered page.
export async function handleCallback(req, res, url, session) {
  const expected = session.oauthState;
  const state = url.searchParams.get('state') || '';
  delete session.oauthState;
  const valid = expected && state.length === expected.length && crypto.timingSafeEqual(Buffer.from(state), Buffer.from(expected));
  if (!valid) return redirect(res, '/connect-error');
  try {
    const c = await client();
    const authResponse = await c.createToken(req.url);
    await saveCompany({
      refreshToken: encrypt(authResponse.token.refresh_token),
      realmId: encrypt(url.searchParams.get('realmId')),
    });
    redirect(res, '/dashboard');
  } catch {
    redirect(res, '/connect-error');
  }
}
