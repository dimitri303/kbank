/**
 * K Bank — Implicit Flow Authentication
 * Auth0 returns id_token directly (no code exchange).
 * Genesys receives the id_token via setTokens, verifies against Auth0 JWKS.
 *
 * Flow:
 * 1. User clicks Log In -> redirect to Auth0 with response_type=id_token token
 * 2. Auth0 redirects back with id_token in URL hash fragment
 * 3. We parse the id_token, save user name to localStorage, strip hash from URL
 * 4. Genesys loads, AuthProvider registers, calls getAuthCode (not used in implicit)
 *    OR we proactively call setTokens once AuthProvider is ready
 * 5. Genesys verifies id_token against Auth0 JWKS endpoint
 * 6. Session authenticated, agent sees user identity
 */

const AUTH0_DOMAIN    = 'dev-jio6oy1xm6qkupod.us.auth0.com';
const AUTH0_CLIENT_ID = 'eYTMidZRXEU2sDMTJ9j1Rx2n0KPAbHm6';
const REDIRECT_URI    = 'https://dimitri303.github.io/kbank/index.html';
const KBANK_SESSION_KEY = 'kbank_user';
const KBANK_ID_TOKEN_KEY = 'kbank_id_token';

// ── HELPERS ───────────────────────────────────────────────────────────────────

function parseJWT(token) {
  try {
    let str = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return JSON.parse(atob(str));
  } catch { return null; }
}

function generateNonce(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ── SESSION ───────────────────────────────────────────────────────────────────

function getSession() {
  try {
    const raw = localStorage.getItem(KBANK_SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function clearSession() {
  localStorage.removeItem(KBANK_SESSION_KEY);
  localStorage.removeItem(KBANK_ID_TOKEN_KEY);
  localStorage.removeItem('kbank_auth_nonce');
  localStorage.removeItem('implicit_nonce');
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
          font-size:13px;font-weight:700;letter-spacing:0.03em;flex-shrink:0;
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

// ── LOGIN ─────────────────────────────────────────────────────────────────────

function kbankLoginRedirect() {
  const nonce = generateNonce(16);
  const state = generateNonce(16);
  localStorage.setItem('implicit_nonce', nonce);
  localStorage.setItem('implicit_state', state);

  const params = new URLSearchParams({
    response_type: 'id_token token',
    client_id:     AUTH0_CLIENT_ID,
    redirect_uri:  REDIRECT_URI,
    scope:         'openid profile email',
    nonce,
    state,
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

// ── PARSE IMPLICIT CALLBACK ───────────────────────────────────────────────────
// Auth0 returns tokens in the URL hash fragment for implicit flow.
// We parse it here if present, save user + id_token, then clean the URL.

function parseImplicitCallback() {
  const hash = window.location.hash;
  if (!hash || !hash.includes('id_token')) return null;

  const params = new URLSearchParams(hash.substring(1));
  const idToken    = params.get('id_token');
  const error      = params.get('error');

  // Clean hash from URL immediately
  history.replaceState(null, '', window.location.pathname + window.location.search);

  if (error) {
    console.error('[KBank Auth] Implicit flow error:', error, params.get('error_description'));
    return null;
  }

  if (!idToken) return null;

  const claims = parseJWT(idToken);
  if (!claims) {
    console.error('[KBank Auth] Could not parse id_token');
    return null;
  }

  // Basic nonce check
  const expectedNonce = localStorage.getItem('implicit_nonce');
  if (expectedNonce && claims.nonce && claims.nonce !== expectedNonce) {
    console.error('[KBank Auth] Nonce mismatch -- possible replay attack');
    return null;
  }
  localStorage.removeItem('implicit_nonce');
  localStorage.removeItem('implicit_state');

  const user = {
    firstName: claims.given_name || claims.nickname || (claims.name || '').split(' ')[0] || 'User',
    lastName:  claims.family_name || (claims.name || '').split(' ').slice(1).join(' ') || '',
    email:     claims.email || claims.sub,
  };

  localStorage.setItem(KBANK_SESSION_KEY, JSON.stringify(user));
  localStorage.setItem(KBANK_ID_TOKEN_KEY, idToken);
  localStorage.setItem('kbank_auth_nonce', claims.nonce || '');
  console.log('[KBank Auth] Implicit login success:', user.firstName, user.lastName);

  return { user, idToken };
}

// ── GENESYS AUTH PROVIDER ─────────────────────────────────────────────────────

function registerGenesysAuthProvider() {
  let attempts = 0;

  const tryRegister = () => {
    if (typeof Genesys !== 'function') {
      if (attempts++ < 50) { setTimeout(tryRegister, 300); }
      else { console.warn('[KBank Auth] Genesys SDK not found after timeout'); }
      return;
    }

    Genesys('registerPlugin', 'AuthProvider', (AuthProvider) => {
      console.log('[KBank Auth] AuthProvider plugin ready');

      // For implicit flow, Genesys may call getAuthCode (auth code flow) or
      // we proactively push the id_token via setTokens.
      // We handle both paths.

      AuthProvider.registerCommand('getAuthCode', (e) => {
        console.log('[KBank Auth] getAuthCode called', e.data);
        const { forceUpdate } = e.data || {};

        if (forceUpdate) {
          console.log('[KBank Auth] forceUpdate -- redirecting to login');
          kbankLoginRedirect();
          e.resolve();
          return;
        }

        // Implicit flow: resolve with idToken
        const idToken = localStorage.getItem(KBANK_ID_TOKEN_KEY);
        if (idToken) {
          console.log('[KBank Auth] Resolving getAuthCode with idToken (implicit flow)');
          e.resolve({
            idToken,
            redirectUri: REDIRECT_URI,
            nonce: localStorage.getItem('kbank_auth_nonce') || '',
          });
        } else {
          console.log('[KBank Auth] No idToken -- redirecting to login');
          kbankLoginRedirect();
          e.resolve();
        }
      });

      AuthProvider.registerCommand('reAuthenticate', (e) => {
        console.log('[KBank Auth] reAuthenticate called -- redirecting');
        kbankLoginRedirect();
        e.resolve();
      });

      AuthProvider.subscribe('Auth.ready', () => {
        console.log('[KBank Auth] Auth.ready');
      });

      AuthProvider.subscribe('Auth.authenticated', () => {
        console.log('[KBank Auth] Auth.authenticated -- Genesys session established!');
      });

      AuthProvider.subscribe('Auth.error', (e) => {
        console.warn('[KBank Auth] Auth.error:', (e.data || {}).message);
      });

      AuthProvider.subscribe('Auth.authError', (e) => {
        console.warn('[KBank Auth] Auth.authError:', e);
      });

      // Mandatory
      AuthProvider.ready();
      console.log('[KBank Auth] AuthProvider.ready() called');
    });
  };

  tryRegister();
}

function injectGenesys() {
  if (typeof Genesys === 'function') return; // already loaded

  window['_genesysJs'] = 'Genesys';
  window['Genesys'] = window['Genesys'] || function() {
    (window['Genesys'].q = window['Genesys'].q || []).push(arguments);
  };
  window['Genesys'].t = 1 * new Date();
  window['Genesys'].c = {
    environment: 'prod-euw1',
    deploymentId: '40b483fe-6988-418f-8c47-63678eff3ec4'
  };

  const ys = document.createElement('script');
  ys.async = 1;
  ys.src = 'https://apps.mypurecloud.ie/genesys-bootstrap/genesys.min.js';
  ys.charset = 'utf-8';
  document.head.appendChild(ys);
  console.log('[KBank Auth] Genesys snippet injected');
}

// ── INIT ──────────────────────────────────────────────────────────────────────

function kbankAuthInit() {
  // 1. Check if this is a redirect back from Auth0 implicit flow
  const result = parseImplicitCallback();

  // 2. Load session (may have just been set by parseImplicitCallback)
  const user = result ? result.user : getSession();

  // 3. Update nav
  updateNav(user);

  // 4. Only inject Genesys and register AuthProvider if user is logged in
  if (user && localStorage.getItem(KBANK_ID_TOKEN_KEY)) {
    injectGenesys();
    registerGenesysAuthProvider();
  } else {
    console.log('[KBank Auth] Not logged in -- Genesys not loaded');
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', kbankAuthInit);
} else {
  kbankAuthInit();
}
