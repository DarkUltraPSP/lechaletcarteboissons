// ═══════════════════════════════════════════════════
// Le Chalet Bar — Cloudflare Worker
// Variables d'environnement requises (wrangler secret):
//   ADMIN_PASSWORD_HASH  — SHA-256 du mot de passe
//   GITHUB_TOKEN         — token GitHub (repo scope)
//   JWT_SECRET           — chaîne aléatoire pour signer les JWT
// ═══════════════════════════════════════════════════

const ALLOWED_ORIGINS = [
  'https://darkultrapsp.github.io',
  'http://localhost:8788',
  'http://localhost:8787',
];

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
};

function validateMenuData(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return 'data invalide';
  if (!Array.isArray(data.categories)) return 'categories manquant ou invalide';
  for (const cat of data.categories) {
    if (typeof cat.id !== 'string' || !cat.id) return 'categorie.id invalide';
    if (typeof cat.label !== 'string') return 'categorie.label invalide';
    if (!['simple', 'double_prix'].includes(cat.type)) return `categorie.type invalide: ${cat.type}`;
    if (typeof cat.active !== 'boolean') return 'categorie.active invalide';
    if (cat.type === 'double_prix') {
      if (!Array.isArray(cat.items)) return `categorie "${cat.id}": items manquant`;
      for (const item of cat.items) {
        if (typeof item.id !== 'string' || !item.id) return 'item.id invalide';
        if (typeof item.name !== 'string') return 'item.name invalide';
        if (typeof item.active !== 'boolean') return 'item.active invalide';
        if (item.price1 !== null && item.price1 !== undefined && typeof item.price1 !== 'number') return 'item.price1 invalide';
        if (item.price2 !== null && item.price2 !== undefined && typeof item.price2 !== 'number') return 'item.price2 invalide';
      }
    } else {
      if (!Array.isArray(cat.subsections)) return `categorie "${cat.id}": subsections manquant`;
      for (const sub of cat.subsections) {
        if (typeof sub.id !== 'string' || !sub.id) return 'subsection.id invalide';
        if (typeof sub.label !== 'string') return 'subsection.label invalide';
        if (!Array.isArray(sub.items)) return `subsection "${sub.id}": items manquant`;
        for (const item of sub.items) {
          if (typeof item.id !== 'string' || !item.id) return 'item.id invalide';
          if (typeof item.name !== 'string') return 'item.name invalide';
          if (typeof item.active !== 'boolean') return 'item.active invalide';
          if (item.price !== undefined && item.price !== null && typeof item.price !== 'number') return 'item.price invalide';
        }
      }
    }
  }
  return null;
}

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}

function json(data, status = 200, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(request), ...SECURITY_HEADERS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400, request) {
  return json({ error: msg }, status, request);
}

// ── JWT minimal (HS256 avec Web Crypto) ──
async function signJWT(payload, secret) {
  const header  = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body    = b64url(JSON.stringify(payload));
  const signing = `${header}.${body}`;
  const key     = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signing));
  return `${signing}.${b64url(sig)}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const signing = `${header}.${body}`;
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const valid = await crypto.subtle.verify(
      'HMAC', key,
      b64urlDecode(sig),
      new TextEncoder().encode(signing)
    );
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    if (payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch { return null; }
}

function b64url(data) {
  const str = typeof data === 'string' ? data : String.fromCharCode(...new Uint8Array(data));
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  return new Uint8Array([...bin].map(c => c.charCodeAt(0)));
}

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function pbkdf2Hash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password),
    'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
    key, 256
  );
  const hex = b => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
  return `pbkdf2:${hex(salt)}:${hex(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  if (!stored) return false;
  if (stored.startsWith('pbkdf2:')) {
    const [, saltHex, hashHex] = stored.split(':');
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password),
      'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
      key, 256
    );
    const candidate = Array.from(new Uint8Array(bits)).map(x => x.toString(16).padStart(2, '0')).join('');
    return timingSafeEqual(candidate, hashHex);
  }
  // Rétrocompatibilité : ancien hash SHA-256 brut (env.ADMIN_PASSWORD_HASH)
  const hash = await sha256(password);
  return timingSafeEqual(hash, stored);
}

// ── Auth middleware ──
async function requireAuth(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)chalet_jwt=([^;]+)/);
  const token = match ? match[1] : '';
  if (!token) return null;
  return await verifyJWT(token, env.JWT_SECRET);
}

// ── GitHub helpers ──
async function ghGet(env) {
  const url = `https://api.github.com/repos/${env.REPO}/contents/${env.FILE}?ref=${env.BRANCH}`;
  const res = await fetch(url, {
    headers: {
      Authorization: `token ${env.GITHUB_TOKEN}`,
      Accept: 'application/vnd.github.v3+json',
      'User-Agent': 'chalet-bar-worker',
    },
  });
  if (!res.ok) throw new Error(`GitHub GET failed: ${res.status}`);
  return res.json();
}

async function ghPut(env, content, sha, message) {
  const url = `https://api.github.com/repos/${env.REPO}/contents/${env.FILE}`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `token ${env.GITHUB_TOKEN}`,
      Accept: 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
      'User-Agent': 'chalet-bar-worker',
    },
    body: JSON.stringify({ message, content, sha, branch: env.BRANCH }),
  });
  if (!res.ok) { const j = await res.json(); throw new Error(j.message || res.status); }
  return res.json();
}

function b64enc(str) {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (_, p) => String.fromCharCode('0x' + p)));
}
function b64dec(str) {
  return decodeURIComponent(atob(str.replace(/\n/g, '')).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
}

// ═══════════════════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════════════════
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Preflight CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...corsHeaders(request), 'Access-Control-Max-Age': '86400' } });
    }

    // ── POST /login ──
    if (url.pathname === '/login' && request.method === 'POST') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const { success } = await env.RATE_LIMITER.limit({ key: ip });
      if (!success) return err('Trop de tentatives. Réessaie dans une minute.', 429, request);
      try {
        const { password } = await request.json();
        if (!password) return err('Mot de passe requis.', 400, request);
        // menu.json:admin_password (posé par /change-password) est prioritaire sur env
        let storedHash = env.ADMIN_PASSWORD_HASH;
        try {
          const gh = await ghGet(env);
          const data = JSON.parse(b64dec(gh.content));
          if (data.admin_password) storedHash = data.admin_password;
        } catch { /* env reste le fallback */ }
        if (!await verifyPassword(password, storedHash)) return err('Mot de passe incorrect.', 401, request);
        const token = await signJWT(
          { sub: 'admin', exp: Math.floor(Date.now() / 1000) + 86400 * 30 }, // 30 jours
          env.JWT_SECRET
        );
        const cookieHeader = `chalet_jwt=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=2592000`;
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { ...corsHeaders(request), 'Content-Type': 'application/json', 'Set-Cookie': cookieHeader },
        });
      } catch (e) { return err('Erreur serveur.', 500, request); }
    }

    // ── GET /verify ── (protégé — vérifie le JWT)
    if (url.pathname === '/verify' && request.method === 'GET') {
      const payload = await requireAuth(request, env);
      if (!payload) return err('Non autorisé.', 401, request);
      return json({ ok: true }, 200, request);
    }

    // ── GET /menu ── (public — pour index.html)
    if (url.pathname === '/menu' && request.method === 'GET') {
      try {
        const gh = await ghGet(env);
        const data = JSON.parse(b64dec(gh.content));
        // On retire le mot de passe avant de renvoyer
        delete data.admin_password;
        return json({ data, sha: gh.sha }, 200, request);
      } catch (e) { return err('Erreur serveur.', 500, request); }
    }

    // ── PUT /menu ── (protégé)
    if (url.pathname === '/menu' && request.method === 'PUT') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const { success } = await env.RATE_LIMITER.limit({ key: ip });
      if (!success) return err('Trop de tentatives. Réessaie dans une minute.', 429, request);
      const payload = await requireAuth(request, env);
      if (!payload) return err('Non autorisé.', 401, request);
      try {
        const { data, sha, message } = await request.json();
        const validationError = validateMenuData(data);
        if (validationError) return err(validationError, 400, request);
        // Récupérer le vrai menu.json pour conserver le hash du mdp
        const gh = await ghGet(env);
        const current = JSON.parse(b64dec(gh.content));
        // Fusionner : données envoyées + mot de passe existant
        data.admin_password = current.admin_password;
        const content = b64enc(JSON.stringify(data, null, 2));
        const result = await ghPut(env, content, sha || gh.sha, message || 'Mise à jour carte');
        return json({ sha: result.content.sha }, 200, request);
      } catch (e) { return err('Erreur serveur.', 500, request); }
    }

    // ── POST /change-password ── (protégé)
    if (url.pathname === '/change-password' && request.method === 'POST') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const { success } = await env.RATE_LIMITER.limit({ key: ip });
      if (!success) return err('Trop de tentatives. Réessaie dans une minute.', 429, request);
      const payload = await requireAuth(request, env);
      if (!payload) return err('Non autorisé.', 401, request);
      try {
        const { password, oldPassword } = await request.json();
        if (!password || !oldPassword) return err('Mot de passe requis.', 400, request);
        let storedHash = env.ADMIN_PASSWORD_HASH;
        const gh = await ghGet(env);
        const current = JSON.parse(b64dec(gh.content));
        if (current.admin_password) storedHash = current.admin_password;
        if (!await verifyPassword(oldPassword, storedHash)) return err('Ancien mot de passe incorrect.', 401, request);
        const hash = await pbkdf2Hash(password);
        current.admin_password = hash;
        const content = b64enc(JSON.stringify(current, null, 2));
        await ghPut(env, content, gh.sha, 'Mot de passe admin modifié');
        return json({ ok: true }, 200, request);
      } catch (e) { return err('Erreur serveur.', 500, request); }
    }

    // ── POST /logout ──
    if (url.pathname === '/logout' && request.method === 'POST') {
      const cookieHeader = 'chalet_jwt=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0';
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { ...corsHeaders(request), 'Content-Type': 'application/json', 'Set-Cookie': cookieHeader },
      });
    }

    return err('Route introuvable.', 404, request);
  },
};
