// ═══════════════════════════════════════════════════
// Le Chalet Bar — Cloudflare Worker
// Variables d'environnement requises (wrangler secret):
//   ADMIN_PASSWORD_HASH  — SHA-256 du mot de passe
//   GITHUB_TOKEN         — token GitHub (repo scope)
//   JWT_SECRET           — chaîne aléatoire pour signer les JWT
// ═══════════════════════════════════════════════════

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
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

// ── Auth middleware ──
async function requireAuth(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
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
      return new Response(null, { status: 204, headers: CORS });
    }

    // ── POST /login ──
    if (url.pathname === '/login' && request.method === 'POST') {
      try {
        const { password } = await request.json();
        if (!password) return err('Mot de passe requis.');
        const hash = await sha256(password);
        if (hash !== env.ADMIN_PASSWORD_HASH) return err('Mot de passe incorrect.', 401);
        const token = await signJWT(
          { sub: 'admin', exp: Math.floor(Date.now() / 1000) + 86400 * 30 }, // 30 jours
          env.JWT_SECRET
        );
        return json({ token });
      } catch (e) { return err(e.message, 500); }
    }

    // ── GET /menu ── (public — pour index.html)
    if (url.pathname === '/menu' && request.method === 'GET') {
      try {
        const gh = await ghGet(env);
        const data = JSON.parse(b64dec(gh.content));
        // On retire le mot de passe avant de renvoyer
        delete data.admin_password;
        return json({ data, sha: gh.sha });
      } catch (e) { return err(e.message, 500); }
    }

    // ── PUT /menu ── (protégé)
    if (url.pathname === '/menu' && request.method === 'PUT') {
      const payload = await requireAuth(request, env);
      if (!payload) return err('Non autorisé.', 401);
      try {
        const { data, sha, message } = await request.json();
        // Récupérer le vrai menu.json pour conserver le hash du mdp
        const gh = await ghGet(env);
        const current = JSON.parse(b64dec(gh.content));
        // Fusionner : données envoyées + mot de passe existant
        data.admin_password = current.admin_password;
        const content = b64enc(JSON.stringify(data, null, 2));
        const result = await ghPut(env, content, sha || gh.sha, message || 'Mise à jour carte');
        return json({ sha: result.content.sha });
      } catch (e) { return err(e.message, 500); }
    }

    // ── POST /change-password ── (protégé)
    if (url.pathname === '/change-password' && request.method === 'POST') {
      const payload = await requireAuth(request, env);
      if (!payload) return err('Non autorisé.', 401);
      try {
        const { password } = await request.json();
        if (!password) return err('Mot de passe requis.');
        const hash = await sha256(password);
        // Mettre à jour la variable secrète n'est pas possible à runtime —
        // on stocke le hash dans un KV ou on le met dans menu.json (chiffré côté worker)
        // Solution : on écrit le hash dans menu.json mais UNIQUEMENT lisible par le worker
        const gh = await ghGet(env);
        const current = JSON.parse(b64dec(gh.content));
        current.admin_password = hash;
        const content = b64enc(JSON.stringify(current, null, 2));
        await ghPut(env, content, gh.sha, 'Mot de passe admin modifié');
        return json({ ok: true });
      } catch (e) { return err(e.message, 500); }
    }

    return err('Route introuvable.', 404);
  },
};
