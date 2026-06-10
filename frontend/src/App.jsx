/**
 * OAuth 2.0 + OpenID Connect Demo — Frontend
 * ISTE-442 Secure Web Application Development
 *
 * Security note: This SPA never handles tokens directly.
 * All auth state is managed via the backend session.
 * The browser holds only an HttpOnly session cookie.
 */

import { useState, useEffect } from 'react';
import './App.css';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:3001';

// ─────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────

function LoginPage({ onLogin, error }) {
  return (
    <div className="page login-page">
      <div className="login-card">
        <div className="login-logo">🔐</div>
        <h1>OAuth 2.0 + OIDC Demo</h1>
        <p className="login-subtitle">
          Secure authentication via Authorization Code Flow with PKCE
        </p>
        {error && (
          <div className="error-banner">
            <span>⚠️</span> {error}
          </div>
        )}
        <button className="btn btn-primary btn-login" onClick={onLogin}>
          Sign in with Auth0
        </button>
        <div className="login-info">
          <p>This demo implements:</p>
          <ul>
            <li>Authorization Code Flow + PKCE (RFC 7636)</li>
            <li>OpenID Connect ID Token validation</li>
            <li>Backend-for-Frontend (no tokens in browser)</li>
            <li>CSRF protection via state parameter</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

function ProfileCard({ user }) {
  const authTime = user.auth_time
    ? new Date(user.auth_time * 1000).toLocaleString()
    : 'N/A';
  const sessionExpires = user.session_expires
    ? new Date(user.session_expires).toLocaleString()
    : 'N/A';

  return (
    <div className="profile-card">
      <div className="profile-header">
        {user.picture ? (
          <img src={user.picture} alt="Profile" className="avatar" referrerPolicy="no-referrer" />
        ) : (
          <div className="avatar-placeholder">{(user.name || user.email || '?')[0].toUpperCase()}</div>
        )}
        <div className="profile-name-block">
          <h2>{user.name || 'Unknown'}</h2>
          <span className={`badge ${user.email_verified ? 'badge-green' : 'badge-yellow'}`}>
            {user.email_verified ? '✓ Email Verified' : '⚠ Email Unverified'}
          </span>
        </div>
      </div>
      <div className="claims-table">
        <h3>OpenID Connect Claims (from ID Token)</h3>
        <table>
          <thead>
            <tr><th>Claim</th><th>Value</th><th>Description</th></tr>
          </thead>
          <tbody>
            <tr>
              <td><code>sub</code></td>
              <td className="mono">{user.sub}</td>
              <td>Subject — stable unique user ID</td>
            </tr>
            <tr>
              <td><code>name</code></td>
              <td>{user.name}</td>
              <td>Full display name</td>
            </tr>
            <tr>
              <td><code>email</code></td>
              <td>{user.email}</td>
              <td>Email address</td>
            </tr>
            <tr>
              <td><code>email_verified</code></td>
              <td>{String(user.email_verified)}</td>
              <td>Provider-verified email</td>
            </tr>
            <tr>
              <td><code>auth_time</code></td>
              <td>{authTime}</td>
              <td>Time of authentication</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div className="session-info">
        <p>⏱ Session expires: <strong>{sessionExpires}</strong></p>
      </div>
    </div>
  );
}

function ProtectedResourceDemo() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchProtected = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/protected`, {
        credentials: 'include',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="protected-demo">
      <h3>Protected Resource Demo</h3>
      <p>Clicking the button calls <code>GET /api/protected</code> - requires active session.</p>
      <button className="btn btn-secondary" onClick={fetchProtected} disabled={loading}>
        {loading ? 'Fetching...' : 'Access Protected Resource'}
      </button>
      {error && <div className="error-banner">⚠️ {error}</div>}
      {result && (
        <pre className="response-pre">{JSON.stringify(result, null, 2)}</pre>
      )}
    </div>
  );
}

function FlowDiagram() {
  return (
    <div className="flow-diagram">
      <h3>Authorization Code Flow with PKCE</h3>
      <div className="flow-steps">
        {[
          { step: '1', label: 'Generate PKCE', detail: 'code_verifier → SHA-256 → code_challenge', actor: 'Backend' },
          { step: '2', label: 'Authorize Request', detail: 'Redirect to /authorize with code_challenge + state', actor: 'Browser → Auth0' },
          { step: '3', label: 'User Login', detail: 'Auth0 handles credentials — app never sees password', actor: 'Auth0' },
          { step: '4', label: 'Code Return', detail: 'Auth0 redirects to /callback?code=...&state=...', actor: 'Auth0 → Backend' },
          { step: '5', label: 'Token Exchange', detail: 'POST /oauth/token with code + code_verifier', actor: 'Backend → Auth0' },
          { step: '6', label: 'Token Validation', detail: 'Verify ID token signature (RS256, JWKS)', actor: 'Backend' },
          { step: '7', label: 'Session Created', detail: 'Claims stored server-side; HttpOnly cookie issued', actor: 'Backend → Browser' },
        ].map(({ step, label, detail, actor }) => (
          <div key={step} className="flow-step">
            <div className="step-number">{step}</div>
            <div className="step-body">
              <strong>{label}</strong>
              <span className="step-detail">{detail}</span>
              <span className="step-actor">{actor}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Dashboard({ user, onLogout }) {
  const [activeTab, setActiveTab] = useState('profile');

  return (
    <div className="page dashboard">
      <header className="dash-header">
        <div className="dash-title">
          <span className="lock-icon">🔐</span>
          <span>OAuth 2.0 + OIDC Demo</span>
        </div>
        <div className="dash-user">
          {user.picture && (
            <img src={user.picture} alt="" className="header-avatar" referrerPolicy="no-referrer" />
          )}
          <span>{user.email}</span>
          <button className="btn btn-outline" onClick={onLogout}>
            Sign Out
          </button>
        </div>
      </header>

      <div className="dash-nav">
        {['profile', 'protected', 'flow'].map(tab => (
          <button
            key={tab}
            className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {{ profile: '👤 Profile', protected: '🔒 Protected Resource', flow: '📊 Auth Flow' }[tab]}
          </button>
        ))}
      </div>

      <div className="dash-content">
        {activeTab === 'profile'    && <ProfileCard user={user} />}
        {activeTab === 'protected'  && <ProtectedResourceDemo />}
        {activeTab === 'flow'       && <FlowDiagram />}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Root App
// ─────────────────────────────────────────────────────────────
export default function App() {
  const [user, setUser]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  // Check for error in URL (redirected from backend on failure)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const urlError = params.get('error');
    if (urlError) {
      setError(decodeURIComponent(urlError));
      window.history.replaceState({}, '', '/');
    }
  }, []);

  // On mount: check if a session already exists
  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const res  = await fetch(`${API_BASE}/api/auth/status`, { credentials: 'include' });
      const data = await res.json();
      if (data.authenticated) {
        await loadProfile();
      }
    } catch (err) {
      console.error('Auth check failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadProfile = async () => {
    const res  = await fetch(`${API_BASE}/api/profile`, { credentials: 'include' });
    if (!res.ok) return;
    const data = await res.json();
    setUser(data);
  };

  const handleLogin = () => {
    // Redirect browser to backend /login which initiates PKCE flow
    window.location.href = `${API_BASE}/login`;
  };

  const handleLogout = async () => {
    try {
      const res  = await fetch(`${API_BASE}/logout`, {
        method: 'POST',
        credentials: 'include',
      });
      const { logoutUrl } = await res.json();
      setUser(null);
      // Federated logout: also logs out of Auth0 session
      window.location.href = logoutUrl;
    } catch (err) {
      console.error('Logout failed:', err);
    }
  };

  if (loading) {
    return (
      <div className="page loading-page">
        <div className="spinner" />
        <p>Checking authentication status...</p>
      </div>
    );
  }

  if (!user) {
    return <LoginPage onLogin={handleLogin} error={error} />;
  }

  return <Dashboard user={user} onLogout={handleLogout} />;
}
