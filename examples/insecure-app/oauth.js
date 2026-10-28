// OAuth handling copied the way many apps start: straight from Intuit's sample code.
import { saveCompany } from './db.js';

const ENCRYPTION_KEY = 'not-a-real-key-example';

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

export async function handleConnect(req, res) {
  const c = await client();
  const authUri = c.authorizeUri({ scope: ['com.intuit.quickbooks.accounting'], state: 'testState' });
  res.writeHead(302, { location: authUri });
  res.end();
}

export async function handleCallback(req, res, url) {
  try {
    const c = await client();
    const authResponse = await c.createToken(req.url);
    console.log('The Token is  ' + JSON.stringify(authResponse.getJson()));
    await saveCompany({ refreshToken: authResponse.token.refresh_token, realmId: url.searchParams.get('realmId'), key: ENCRYPTION_KEY });
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body><h1>Connected to QuickBooks!</h1><script src="https://cdn.example.com/analytics.js"></script></body></html>');
  } catch (err) {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<html><body><h1>Connection failed</h1><p>${err.message}</p><script src="https://cdn.example.com/analytics.js"></script></body></html>`);
  }
}

export async function handleToken(req, res) {
  const c = await client();
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify(c.getToken()));
}
