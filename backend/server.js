/**
 * OAuth 2.0 + OpenID Connect Demo Backend
 * ISTE-442 Secure Web Application Development
 *
 * Implements:
 *   - Authorization Code Flow with PKCE (RFC 7636)
 *   - OpenID Connect ID Token validation (RS256)
 *   - Backend-for-Frontend pattern (tokens never sent to browser)
 *   - CSRF protection via state parameter
 *   - Session-backed authentication middleware
 */

require('dotenv').config();

const express    = require('express');
const session    = require('express-session');
const cors       = require('cors');
const crypto     = require('crypto');
const axios      = require('axios');
const jwksRsa    = require('jwks-rsa');
const jwt        = require('jsonwebtoken');

const app = express();
app.use(express.json());

// ─────────────────────────────────────────────────────────────
// CORS — only allow the specific frontend origin
// Wildcard (*) would break credentialed requests anyway, but
// explicit origin is also a security boundary.
// ─────────────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,  // required for session cookies
}));

// ─────────────────────────────────────────────────────────────
// SESSION — HttpOnly cookie, server stores tokens (BFF pattern)
// NOTE: MemoryStore is development-only.
//       Production: use connect-redis or connect-pg-simple.
// ─────────────────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || (() => { throw new Error('SESSION_SECRET not set'); })(),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true in prod (HTTPS)
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 60 * 60 * 1000, // 1 hour
  },
}));

// ─────────────────────────────────────────────────────────────
// JWKS CLIENT — fetches Auth0's public RSA keys for ID token
// verification. Keys are cached (10 min) to avoid per-request
// network calls while still rotating on expiry.
// ─────────────────────────────────────────────────────────────
const jwksClient = jwksRsa({
  jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000, // 10 minutes
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

function getSigningKey(header, callback) {
  jwksClient.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

/**
 * Validate an OIDC ID Token:
 *   1. Signature — RS256 using issuer's public key from JWKS
 *   2. Issuer    — must match AUTH0_DOMAIN
 *   3. Audience  — must match AUTH0_CLIENT_ID (prevents token reuse)
 *   4. Expiry    — jwt.verify rejects expired tokens automatically
 *   5. Algorithm — pinned to RS256 (prevents algorithm confusion)
 */
function validateIdToken(idToken) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      idToken,
      getSigningKey,
      {
        audience:   process.env.AUTH0_CLIENT_ID,
        issuer:     `https://${process.env.AUTH0_DOMAIN}/`,
        algorithms: ['RS256'],
      },
      (err, decoded) => {
        if (err) return reject(err);
        resolve(decoded);
      }
    );
  });
}

// ─────────────────────────────────────────────────────────────
// AUTH MIDDLEWARE — protects API routes
// ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Unauthorized', message: 'No active session' });
  }
  next();
}

// ─────────────────────────────────────────────────────────────
// ROUTE: GET /login
// Initiates Authorization Code Flow with PKCE.
//   1. Generate code_verifier (random 32 bytes → base64url)
//   2. Derive code_challenge = BASE64URL(SHA256(code_verifier))
//   3. Generate state (CSRF token)
//   4. Store verifier + state in server session
//   5. Redirect browser to Auth0 /authorize
// ─────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  // PKCE: code verifier is high-entropy random value
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  // code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  // State: random nonce for CSRF protection
  const state = crypto.randomBytes(16).toString('hex');

  // Store server-side — NEVER send these to the browser
  req.session.codeVerifier  = codeVerifier;
  req.session.oauthState    = state;

  const params = new URLSearchParams({
    response_type:          'code',
    client_id:              process.env.AUTH0_CLIENT_ID,
    redirect_uri:           process.env.CALLBACK_URL,
    scope:                  'openid profile email',
    state:                  state,
    code_challenge:         codeChallenge,
    code_challenge_method:  'S256',
  });

  res.redirect(`https://${process.env.AUTH0_DOMAIN}/authorize?${params}`);
});

// ─────────────────────────────────────────────────────────────
// ROUTE: GET /callback
// Handles the authorization code return from Auth0.
//   1. Validate state (CSRF check)
//   2. Exchange code + code_verifier for tokens
//   3. Validate ID token (JWT signature + claims)
//   4. Store user claims in session (tokens stay server-side)
//   5. Redirect to frontend dashboard
// ─────────────────────────────────────────────────────────────
app.get('/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // Handle provider-side errors (e.g., user denied consent)
  if (error) {
    console.error('Auth provider error:', error, error_description);
    return res.redirect(
      `${process.env.FRONTEND_URL}/?error=${encodeURIComponent(error_description || error)}`
    );
  }

  if (!code) {
    return res.status(400).send('Missing authorization code');
  }

  // ── CSRF CHECK ──────────────────────────────────────────
  // If state doesn't match what we stored, abort immediately.
  if (!state || state !== req.session.oauthState) {
    console.warn('State mismatch — possible CSRF attack');
    return res.status(400).send('Invalid state parameter');
  }

  const savedVerifier = req.session.codeVerifier;
  if (!savedVerifier) {
    return res.status(400).send('Missing code verifier');
  }

  // Clear one-time values from session
  delete req.session.codeVerifier;
  delete req.session.oauthState;

  try {
    // ── TOKEN EXCHANGE ────────────────────────────────────
    // Server-to-server POST — browser is not involved.
    // Auth0 verifies SHA256(code_verifier) === stored code_challenge.
    const tokenResponse = await axios.post(
      `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
      {
        grant_type:    'authorization_code',
        client_id:     process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        code:          code,
        redirect_uri:  process.env.CALLBACK_URL,
        code_verifier: savedVerifier,
      },
      { headers: { 'Content-Type': 'application/json' } }
    );

    const { id_token, access_token, expires_in } = tokenResponse.data;

    // ── ID TOKEN VALIDATION ──────────────────────────────
    // Verifies: signature (RS256), iss, aud, exp
    const userClaims = await validateIdToken(id_token);

    // ── SESSION ESTABLISHMENT ────────────────────────────
    // Only store the decoded, validated claims + access token.
    // Raw JWT strings are not persisted in session storage.
    req.session.user = {
      sub:            userClaims.sub,
      name:           userClaims.name,
      email:          userClaims.email,
      email_verified: userClaims.email_verified,
      picture:        userClaims.picture,
      iss:            userClaims.iss,
      aud:            userClaims.aud,
      auth_time:      userClaims.auth_time,
    };
    // Access token stored server-side for potential API calls
    req.session.accessToken = access_token;
    req.session.tokenExpiry = Date.now() + (expires_in * 1000);

    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);

  } catch (err) {
    const detail = err.response?.data || err.message;
    console.error('Token exchange / validation error:', detail);
    res.redirect(
      `${process.env.FRONTEND_URL}/?error=${encodeURIComponent('Authentication failed')}`
    );
  }
});

// ─────────────────────────────────────────────────────────────
// ROUTE: GET /api/auth/status
// Public endpoint — tells the frontend whether a session exists.
// ─────────────────────────────────────────────────────────────
app.get('/api/auth/status', (req, res) => {
  res.json({
    authenticated: !!(req.session && req.session.user),
  });
});

// ─────────────────────────────────────────────────────────────
// ROUTE: GET /api/profile  [PROTECTED]
// Returns OIDC claims for the authenticated user.
// Returns 401 if no valid session.
// ─────────────────────────────────────────────────────────────
app.get('/api/profile', requireAuth, (req, res) => {
  const { sub, name, email, picture, email_verified, auth_time } = req.session.user;
  res.json({
    sub,
    name,
    email,
    picture,
    email_verified,
    auth_time,
    session_expires: req.session.tokenExpiry,
  });
});

// ─────────────────────────────────────────────────────────────
// ROUTE: GET /api/protected  [PROTECTED — demo resource]
// Simulates a protected API resource accessible post-authentication.
// ─────────────────────────────────────────────────────────────
app.get('/api/protected', requireAuth, (req, res) => {
  res.json({
    message: 'You have accessed a protected resource.',
    resource_id: crypto.randomUUID(),
    accessed_by: req.session.user.sub,
    accessed_at: new Date().toISOString(),
    scopes_granted: ['openid', 'profile', 'email'],
  });
});

// ─────────────────────────────────────────────────────────────
// ROUTE: POST /logout
// Destroys the server-side session and returns the Auth0
// logout URL for the client to redirect to (federated logout).
// ─────────────────────────────────────────────────────────────
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Session destroy error:', err);

    const auth0LogoutUrl = `https://${process.env.AUTH0_DOMAIN}/v2/logout?` +
      new URLSearchParams({
        client_id: process.env.AUTH0_CLIENT_ID,
        returnTo:  process.env.FRONTEND_URL,
      });

    res.json({ logoutUrl: auth0LogoutUrl });
  });
});

// ─────────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n🔐 OAuth 2.0 + OIDC Backend`);
  console.log(`   Listening on http://localhost:${PORT}`);
  console.log(`   Identity Provider: https://${process.env.AUTH0_DOMAIN}`);
  console.log(`   Frontend Origin:   ${process.env.FRONTEND_URL}\n`);
});
