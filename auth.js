/**
 * K Bank — Auth0 OIDC Authentication
 * Uses Genesys AuthProvider plugin + getAuthCode command.
 * Genesys calls getAuthCode → we initiate a fresh Auth0 login to get a new code
 * → Auth0 redirects to callback.html → we store code → redirect back →
 * Genesys calls getAuthCode again → we supply the code → Genesys exchanges it.
 */

const AUTH0_DOMAIN    = 'dev-jio6oy1xm6qkupod.us.auth0.com';
const AUTH0_CLIENT_ID = 'eYTMidZRXEU2sDMTJ9j1Rx2n0KPAbHm6';
const REDIRECT_URI    = 'https://dimitri303.github.io/kbank/callback.html';
const KBANK_SESSION_KEY = 'kbank_user';

// ── PKCE HELPERS ─────────────────────────────────────────────────────────────

function generateRandomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => chars[b % chars.length]).join('');
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return JSON.parse(atob(str));
}

function parseJWT(token) {
  try { return base64UrlDecode(token.split('.')[1]); }
  catch { return null; }
}

// ── SESSION ───────────────────────────────────────────────────────────────────

function getSession() {
  try {
    const raw = localStorage.getItem(KBANK_SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function saveSession(user) {
  localStorage.setItem(KBANK_SESSION_KEY, JSON.stringify(user));
}

function clearSession() {
  localStorage.removeItem(KBANK_SESSION_KEY);
  localStorage.removeItem('pkce_verifier');
  localStorage.removeItem('pkce_state');
  localStorage.removeItem('genesys_auth_code');
  localStorage.removeItem('genesys_auth_verifier');
}

function getInitials(firstName, lastName) {
  const f = (firstName || '?').charAt(0).toUpperCase();
  const l = (lastName  || '').charAt(0).toUpperCase();
  return l ? `${f}${l}` : f;
}

// ── NAV ───────────────────────────────────────────────────────────────────────

function updateNav(user) {
  const navCta = document.querySelector('.nav-cta');
  if (!navCta) return;

  if (user) {
    navCta.innerHTML = `
      <div style="display:flex;align-items:center;gap:14px;">
        <div style="
          width:38px;height:38px;border-radius:50%;
          background:var(--purple);color:white;
          display:flex;align-items:center;justify-content:center;
          font-size:13px;font-weight:700;letter-spacing:0.03em;
          flex-shrink:0;
        ">${getInitials(user.firstName, user.lastName)}</div>
        <span style="font-size:15px;font-weight:500;color:var(--text);">
          ${user.firstName}
        </span>
        <button onclick="kbankLogout()" style="
          font-family:'DM Sans',sans-serif;font-size:13px;font-weight:500;
          color:var(--grey);background:none;border:none;cursor:pointer;
          padding:0;text-decoration:underline;text-underline-offset:2px;
        ">Log out</button>
      </div>
    `;
  } else {
    navCta.innerHTML = `
      <button class="btn-ghost" onclick="kbankLoginRedirect()">Log In</button>
      <button class="btn-primary" onclick="kbankLoginRedirect()">Open Account</button>
    `;
  }
}

// ── GENESYS AUTH PROVIDER ─────────────────────────────────────────────────────
// Genesys calls getAuthCode when it needs to authenticate the session.
// We initiate a silent/prompt=none Auth0 request to get a fresh code,
// then hand it back to Genesys with the redirect URI.

function registerGenesysAuthProvider() {
  let attempts = 0;

  const tryRegister = () => {
    if (typeof Genesys === 'function') {
      Genesys('registerPlugin', 'AuthProvider', (AuthProvider) => {
        console.log('[KBank Auth] AuthProvider plugin ready');

        AuthProvider.registerCommand('getAuthCode', async (e) => {
          console.log('[KBank Auth] Genesys called getAuthCode');

          // Check if we have a pending code from a recent Auth0 redirect
          const pendingCode    = localStorage.getItem('genesys_auth_code');
          const pendingVerifier = localStorage.getItem('genesys_auth_verifier');

          if (pendingCode && pendingVerifier) {
            console.log('[KBank Auth] Resolving getAuthCode with stored code');
            localStorage.removeItem('genesys_auth_code');
            localStorage.removeItem('genesys_auth_verifier');
            e.resolve({
              authCode:    pendingCode,
              redirectUri: REDIRECT_URI,
            });
            return;
          }

          // No pending code — initiate Auth0 login flow for Genesys
          // Use prompt=none if user is already logged in (silent auth)
          const verifier  = generateRandomString(64);
          const state     = 'genesys_' + generateRandomString(16);
          const challenge = await generateCodeChallenge(verifier);

          localStorage.setItem('genesys_pkce_verifier', verifier);
          localStorage.setItem('genesys_pkce_state', state);

          const params = new URLSearchParams({
            response_type:         'code',
            client_id:             AUTH0_CLIENT_ID,
            redirect_uri:          REDIRECT_URI,
            scope:                 'openid profile email',
            state,
            code_challenge:        challenge,
            code_challenge_method: 'S256',
            prompt:                'none', // silent — user already authenticated
          });

          console.log('[KBank Auth] Redirecting to Auth0 for Genesys code (silent)');
          window.location.href = `https://${AUTH0_DOMAIN}/authorize?${params}`;
        });

      });

      // Trigger auth flow so Genesys calls getAuthCode
      setTimeout(() => {
        console.log('[KBank Auth] Triggering Auth.authorize');
        Genesys('command', 'Auth.authorize');
      }, 1500);

    } else if (attempts++ < 30) {
      setTimeout(tryRegister, 300);
    } else {
      console.warn('[KBank Auth] Genesys SDK not found');
    }
  };

  tryRegister();
}

// ── LOGIN: user-initiated redirect to Auth0 ───────────────────────────────────

async function kbankLoginRedirect() {
  const verifier  = generateRandomString(64);
  const state     = generateRandomString(16);
  const challenge = await generateCodeChallenge(verifier);

  localStorage.setItem('pkce_verifier', verifier);
  localStorage.setItem('pkce_state', state);

  const params = new URLSearchParams({
    response_type:         'code',
    client_id:             AUTH0_CLIENT_ID,
    redirect_uri:          REDIRECT_URI,
    scope:                 'openid profile email',
    state,
    code_challenge:        challenge,
    code_challenge_method: 'S256',
  });

  window.location.href = `https://${AUTH0_DOMAIN}/authorize?${params}`;
}

// ── LOGOUT ────────────────────────────────────────────────────────────────────

function kbankLogout() {
  clearSession();
  if (typeof Genesys === 'function') {
    try { Genesys('command', 'Auth.logout'); } catch {}
  }
  const params = new URLSearchParams({
    client_id: AUTH0_CLIENT_ID,
    returnTo:  'https://dimitri303.github.io/kbank/index.html',
  });
  window.location.href = `https://${AUTH0_DOMAIN}/oidc/logout?${params}`;
}

// ── INIT ──────────────────────────────────────────────────────────────────────

function kbankAuthInit() {
  const user = getSession();
  updateNav(user);
  if (user) {
    registerGenesysAuthProvider();
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', kbankAuthInit);
} else {
  kbankAuthInit();
}
