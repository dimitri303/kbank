/**
 * K Bank — Auth0 OIDC Authentication
 * Uses Authorization Code flow with PKCE.
 * On login, redirects to Auth0, gets a real ID token,
 * and passes it to Genesys authenticated messaging.
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

// ── GENESYS TOKEN INJECTION ───────────────────────────────────────────────────

function injectGenesysToken(idToken) {
  let attempts = 0;
  const tryInject = () => {
    if (typeof Genesys === 'function') {
      Genesys('command', 'Auth.setToken', { token: idToken });
      console.log('[KBank Auth] Genesys token injected.');
    } else if (attempts++ < 20) {
      setTimeout(tryInject, 300);
    } else {
      console.warn('[KBank Auth] Genesys SDK not found after retries.');
    }
  };
  tryInject();
}

// ── LOGIN: redirect to Auth0 ──────────────────────────────────────────────────

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

// ── CALLBACK: exchange code for tokens ────────────────────────────────────────

async function kbankHandleCallback() {
  const params     = new URLSearchParams(window.location.search);
  const code       = params.get('code');
  const state      = params.get('state');
  const verifier   = localStorage.getItem('pkce_verifier');
  const savedState = localStorage.getItem('pkce_state');

  if (!code || state !== savedState) {
    console.error('[KBank Auth] Invalid callback state.');
    window.location.href = 'index.html';
    return;
  }

  const tokenRes = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type:    'authorization_code',
      client_id:     AUTH0_CLIENT_ID,
      code,
      redirect_uri:  REDIRECT_URI,
      code_verifier: verifier,
    }),
  });

  const tokens = await tokenRes.json();

  if (!tokens.id_token) {
    console.error('[KBank Auth] Token exchange failed:', tokens);
    window.location.href = 'index.html';
    return;
  }

  const claims = parseJWT(tokens.id_token);
  const user = {
    firstName: claims.given_name || claims.nickname || (claims.name || '').split(' ')[0] || 'User',
    lastName:  claims.family_name || (claims.name || '').split(' ').slice(1).join(' ') || '',
    email:     claims.email || claims.sub,
    idToken:   tokens.id_token,
  };

  saveSession(user);
  localStorage.removeItem('pkce_verifier');
  localStorage.removeItem('pkce_state');

  injectGenesysToken(tokens.id_token);
  setTimeout(() => { window.location.href = 'index.html'; }, 200);
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

// ── INIT: runs on every page load ─────────────────────────────────────────────

function kbankAuthInit() {
  const user = getSession();
  updateNav(user);
  if (user && user.idToken) {
    injectGenesysToken(user.idToken);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', kbankAuthInit);
} else {
  kbankAuthInit();
}
