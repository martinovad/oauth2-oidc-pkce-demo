# OAuth 2.0 + OpenID Connect Demo Application
## ISTE-442 Secure Web Application Development

A fully working demonstration of OAuth 2.0 Authorization Code Flow with PKCE
and OpenID Connect, built with Node.js/Express (backend) and React (frontend),
using Auth0 as the identity provider.

---

## Architecture Overview

```
┌──────────────────┐     (1) Login click      ┌──────────────────────┐
│                  │ ────────────────────────► │                      │
│  React Frontend  │     (7) Session cookie   │  Express Backend     │
│  :3000           │ ◄──────────────────────── │  :3001               │
│                  │                           │                      │
└──────────────────┘                           └──────────┬───────────┘
                                                          │
                              (2) /authorize redirect     │  (5) POST /oauth/token
                              (4) ?code=...&state=...     │  (6) { id_token, access_token }
                                                          │
                                               ┌──────────▼───────────┐
                                               │  Auth0 Tenant        │
                                               │  (Identity Provider) │
                                               │                      │
                                               │  /authorize          │
                                               │  /oauth/token        │
                                               │  /.well-known/jwks   │
                                               └──────────────────────┘
```

### Security Design: Backend-for-Frontend (BFF)

The browser **never handles tokens**. All OAuth tokens (access, ID) are held
server-side in the Express session. The browser holds only an HttpOnly session
cookie, which cannot be read by JavaScript.

| What lives where | Location |
|-----------------|----------|
| `code_verifier` (PKCE) | Express session (deleted after use) |
| `state` (CSRF nonce) | Express session (deleted after use) |
| `access_token` | Express session only |
| `id_token` claims | Express session only |
| Browser credential | HttpOnly session cookie |

---

## Auth0 Setup (5 minutes)

1. Create a free account at https://auth0.com
2. Go to **Applications → Create Application**
3. Choose **Regular Web Application** → Create
4. In **Settings**, configure:
   - **Allowed Callback URLs**: `http://localhost:3001/callback`
   - **Allowed Logout URLs**: `http://localhost:3000`
   - **Allowed Web Origins**: `http://localhost:3000`
5. Click **Save Changes**
6. Note your **Domain**, **Client ID**, and **Client Secret**

---

## Installation & Setup

### Backend

```bash
cd backend
npm install

# Copy environment template
cp .env.example .env

# Edit .env with your Auth0 values
# Generate a session secret:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

npm run dev   # starts on http://localhost:3001
```

### Frontend

```bash
cd frontend
npm install
npm start     # starts on http://localhost:3000
```

Open http://localhost:3000 and click **Sign in with Auth0**.

---

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `AUTH0_DOMAIN` | Your Auth0 tenant domain | `myapp.auth0.com` |
| `AUTH0_CLIENT_ID` | Application client ID | `abc123...` |
| `AUTH0_CLIENT_SECRET` | Application client secret | `xyz789...` |
| `CALLBACK_URL` | OAuth callback URL | `http://localhost:3001/callback` |
| `FRONTEND_URL` | Frontend origin (for CORS + logout) | `http://localhost:3000` |
| `SESSION_SECRET` | Express session signing secret (32+ chars) | `<random hex>` |
| `PORT` | Backend port | `3001` |

---

## API Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|--------------|-------------|
| GET | `/login` | No | Initiates PKCE Authorization Code Flow |
| GET | `/callback` | No | OAuth2 callback; exchanges code for tokens |
| GET | `/api/auth/status` | No | Returns `{ authenticated: bool }` |
| GET | `/api/profile` | Yes (session) | Returns OIDC claims (sub, name, email, picture) |
| GET | `/api/protected` | Yes (session) | Demo protected resource |
| POST | `/logout` | No | Destroys session; returns Auth0 logout URL |

---

## Authorization Code Flow with PKCE — Sequence

```
Frontend        Backend             Auth0
   │                │                 │
   │  GET /login    │                 │
   │───────────────►│                 │
   │                │ Generate PKCE   │
   │                │ Generate state  │
   │                │ Store in session│
   │  302 → Auth0   │                 │
   │◄───────────────│                 │
   │                │                 │
   │  GET /authorize?code_challenge=..&state=..
   │────────────────────────────────►│
   │                │    User logs in │
   │                │◄────────────────│
   │  302 → /callback?code=X&state=Y │
   │◄────────────────────────────────│
   │                │                 │
   │  GET /callback?code=X&state=Y   │
   │───────────────►│                 │
   │                │ Validate state  │
   │                │ POST /token {code, code_verifier}
   │                │────────────────►│
   │                │  {id_token, access_token}
   │                │◄────────────────│
   │                │ Validate JWT    │
   │                │ Store in session│
   │  302 → /dashboard + session cookie
   │◄───────────────│
   │                │
   │  GET /api/profile (with cookie)
   │───────────────►│
   │  { sub, name, email, picture }
   │◄───────────────│
```

---

## Security Features Implemented

| Requirement | Implementation |
|-------------|---------------|
| PKCE (RFC 7636) | `crypto.randomBytes(32)` → SHA-256 → base64url; verified server-side |
| CSRF protection | `state` parameter generated per-request, validated on callback |
| Token isolation | Tokens stored in Express session; browser gets only HttpOnly cookie |
| ID token validation | RS256 signature via JWKS, `iss`/`aud`/`exp` checks |
| Algorithm pinning | `algorithms: ['RS256']` prevents algorithm confusion attacks |
| CORS restriction | `origin: FRONTEND_URL` (not `*`) |
| Secure cookies | `httpOnly: true`, `sameSite: 'lax'` |

---

## Project Structure

```
oauth-oidc-app/
├── backend/
│   ├── server.js          # Express app — complete OAuth2/OIDC implementation
│   ├── package.json
│   ├── .env.example       # Environment variable template
│   └── .env               # Your secrets (git-ignored)
└── frontend/
    ├── public/
    │   └── index.html
    └── src/
        ├── App.jsx        # React SPA — login, dashboard, profile, demo
        ├── App.css        # Styling
        └── index.js       # Entry point
```
