/**
 * K Bank — Mock Authentication
 * Handles session state, JWT generation, nav rendering,
 * and Genesys authenticated messaging token injection.
 *
 * NOTE: This is a demo-only implementation.
 * The JWT is signed with a static HMAC secret and must NOT
 * be used in any production or real-identity context.
 */

const KBANK_SESSION_KEY = 'kbank_user';

// ── JWT HELPERS ──────────────────────────────────────────────────────────────

function base64UrlEncode(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function objectToBase64Url(obj) {
  return base64UrlEncode(JSON.stringify(obj));
}

/**
 * Build a mock JWT signed with HMAC-SHA256.
 * In a real implementation this would be issued by your OIDC provider.
 */
async function buildMockJWT(user) {
  const header = objectToBase64Url({ alg: 'HS256', typ: 'JWT' });

  const now = Math.floor(Date.now() / 1000);
  const payload = objectToBase64Url({
    iss: 'https://kbank.demo/auth',
    sub: user.email,
    email: user.email,
    given_name: user.firstName,
    family_name: user.lastName,
    name: `${user.firstName} ${user.lastName}`,
    iat: now,
    exp: now + 3600, // 1 hour
  });

  const signingInput = `${header}.${payload}`;

  // Demo secret — hardcoded for mock purposes only
  const secret = 'kbank-demo-secret-do-not-use-in-production';
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const msgData = encoder.encode(signingInput);

  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );

  const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  const signatureBase64 = base64UrlEncode(String.fromCharCode(...signatureArray));

  return `${signingInput}.${signatureBase64}`;
}

// ── SESSION ──────────────────────────────────────────────────────────────────

function getSession() {
  try {
    const raw = sessionStorage.getItem(KBANK_SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveSession(user) {
  sessionStorage.setItem(KBANK_SESSION_KEY, JSON.stringify(user));
}

function clearSession() {
  sessionStorage.removeItem(KBANK_SESSION_KEY);
}

function getInitials(firstName, lastName) {
  return `${firstName.charAt(0)}${lastName.charAt(0)}`.toUpperCase();
}

// ── NAV ──────────────────────────────────────────────────────────────────────

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
      <button class="btn-ghost" onclick="window.location.href='login.html'">Log In</button>
      <button class="btn-primary" onclick="window.location.href='login.html'">Open Account</button>
    `;
  }
}

// ── GENESYS TOKEN INJECTION ───────────────────────────────────────────────────

function injectGenesysToken(jwt) {
  // Retry a few times in case the Genesys SDK hasn't loaded yet
  let attempts = 0;
  const maxAttempts = 20;

  const tryInject = () => {
    if (typeof Genesys === 'function') {
      Genesys('command', 'Auth.setToken', { token: jwt });
      console.log('[KBank Auth] Genesys token injected.');
    } else if (attempts < maxAttempts) {
      attempts++;
      setTimeout(tryInject, 300);
    } else {
      console.warn('[KBank Auth] Genesys SDK not found after retries.');
    }
  };

  tryInject();
}

// ── LOGOUT ───────────────────────────────────────────────────────────────────

function kbankLogout() {
  clearSession();
  // Tell Genesys to drop the authenticated session
  if (typeof Genesys === 'function') {
    try { Genesys('command', 'Auth.logout'); } catch {}
  }
  window.location.href = 'index.html';
}

// ── INIT (runs on every page load) ───────────────────────────────────────────

async function kbankAuthInit() {
  const user = getSession();
  updateNav(user);

  if (user && user.jwt) {
    injectGenesysToken(user.jwt);
  }
}

// ── LOGIN HANDLER (called from login.html) ───────────────────────────────────

async function kbankLogin(email, password, firstName, lastName, redirectTo) {
  const user = { email, firstName, lastName };
  const jwt = await buildMockJWT(user);
  user.jwt = jwt;

  saveSession(user);

  // Inject token before redirect so it's ready on the next page
  injectGenesysToken(jwt);

  setTimeout(() => {
    window.location.href = redirectTo || 'index.html';
  }, 200);
}

// Auto-init on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', kbankAuthInit);
} else {
  kbankAuthInit();
}
