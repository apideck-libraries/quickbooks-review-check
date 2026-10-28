const crypto = require('node:crypto');
const OAuthClient = require('intuit-oauth');
const { doubleCsrf } = require('csrf-csrf');
const key = Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, 'base64');

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([iv, c.update(plain, 'utf8'), c.final(), c.getAuthTag()]).toString('base64');
}

app.get('/connect', (req, res) => {
  req.session.oauthState = crypto.randomBytes(32).toString('hex');
  res.redirect(oauthClient.authorizeUri({ scope: [OAuthClient.scopes.Accounting], state: req.session.oauthState }));
});

app.get('/callback', async (req, res) => {
  if (req.query.state !== req.session.oauthState) return res.redirect('/error');
  const authResponse = await oauthClient.createToken(req.url);
  await db.companies.upsert({ refreshToken: encrypt(authResponse.token.refresh_token), realmId: encrypt(req.query.realmId) });
  res.redirect('/app');
});
