const OAuthClient = require('intuit-oauth');
const express = require('express');
const db = require('./db');
const ENCRYPTION_KEY = 'a1b2c3d4e5f6a7b8c9d0e1f2';
const app = express();
app.use(require('express-session')({ secret: 'x', cookie: { httpOnly: false } }));
const oauthClient = new OAuthClient({ clientId: process.env.ID, clientSecret: process.env.SECRET, environment: 'sandbox', redirectUri: process.env.CB });

app.get('/connect', (req, res) => {
  const authUri = oauthClient.authorizeUri({ scope: [OAuthClient.scopes.Accounting], state: 'testState' });
  res.redirect(authUri);
});

app.get('/callback', async (req, res) => {
  const authResponse = await oauthClient.createToken(req.url);
  console.log('The Token is  ' + JSON.stringify(authResponse.getJson()));
  await db.query(`UPDATE companies SET refresh_token = '${authResponse.token.refresh_token}' WHERE realm = ${req.query.realmId}`);
  db.companies.save({ refreshToken: authResponse.token.refresh_token, realmId: req.query.realmId });
  res.send('<html><body>Connected!</body></html>');
});

app.get('/token', (req, res) => res.json(oauthClient.getToken()));
