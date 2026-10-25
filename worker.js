// OFRM — serveur des comptes (Cloudflare Worker)
// À coller dans l'éditeur du Worker « ofrm-api ». Il a besoin d'une base D1 liée sous le nom DB.
// Variable facultative : PROMO_CODE (le code promo Stripe montré aux 1000 premiers inscrits).

const ORIGINS = ['https://ofrm.ofrmfrance.workers.dev']; // adresse du site autorisée à appeler ce serveur
const LIMIT = 1000;                                        // nombre d'inscrits qui ont droit à -20 %

function cors(req) {
  const o = req.headers.get('Origin') || '';
  return {
    'Access-Control-Allow-Origin': ORIGINS.includes(o) ? o : ORIGINS[0],
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
    'Vary': 'Origin'
  };
}
const json = (req, data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors(req) } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rand = n => hex(crypto.getRandomValues(new Uint8Array(n)));

// mot de passe : PBKDF2-SHA256, 100 000 itérations, sel aléatoire par compte (jamais stocké en clair)
async function hash(pw, salt) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(salt), iterations: 100000 }, key, 256);
  return hex(bits);
}
function same(a, b) { // comparaison à temps constant
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function newSession(env, userId) {
  const token = rand(32);
  await env.DB.prepare('INSERT INTO sessions (token, user_id, created) VALUES (?, ?, ?)').bind(token, userId, Date.now()).run();
  return token;
}
async function currentUser(req, env) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/, '');
  if (!token) return null;
  return env.DB.prepare('SELECT u.id, u.email, u.cart FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?').bind(token).first();
}
const publicUser = (u, env) => ({
  email: u.email,
  member: u.id,                       // numéro d'inscription : 1 = premier inscrit
  discount: u.id <= LIMIT,            // -20 % pour les 1000 premiers
  code: u.id <= LIMIT ? (env.PROMO_CODE || '') : '',
  cart: JSON.parse(u.cart || '[]')
});

// crée les tables toutes seules au premier appel (plus besoin de la console SQL)
let ready = false;
async function init(env) {
  if (ready) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, pass TEXT NOT NULL, salt TEXT NOT NULL, cart TEXT DEFAULT '[]', created INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER)")
  ]);
  ready = true;
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors(req) });
    await init(env);
    const { pathname } = new URL(req.url);
    try {
      if (pathname === '/stats') {
        const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
        return json(req, { count: r.n, left: Math.max(0, LIMIT - r.n), limit: LIMIT });
      }

      if (pathname === '/signup' && req.method === 'POST') {
        const { email, password } = await req.json();
        const e = String(email || '').trim().toLowerCase();
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) || e.length > 200) return json(req, { error: 'Adresse e-mail invalide.' }, 400);
        if (String(password || '').length < 8) return json(req, { error: 'Le mot de passe doit faire au moins 8 caractères.' }, 400);
        const salt = rand(16), h = await hash(String(password), salt);
        try {
          await env.DB.prepare('INSERT INTO users (email, pass, salt, cart, created) VALUES (?, ?, ?, ?, ?)').bind(e, h, salt, '[]', Date.now()).run();
        } catch (x) {
          return json(req, { error: 'Un compte existe déjà avec cette adresse. Connecte-toi.' }, 409);
        }
        const u = await env.DB.prepare('SELECT id, email, cart FROM users WHERE email = ?').bind(e).first();
        return json(req, { token: await newSession(env, u.id), ...publicUser(u, env) });
      }

      if (pathname === '/login' && req.method === 'POST') {
        const { email, password } = await req.json();
        const e = String(email || '').trim().toLowerCase();
        const u = await env.DB.prepare('SELECT id, email, pass, salt, cart FROM users WHERE email = ?').bind(e).first();
        if (!u || !same(await hash(String(password || ''), u.salt), u.pass)) return json(req, { error: 'E-mail ou mot de passe incorrect.' }, 401);
        return json(req, { token: await newSession(env, u.id), ...publicUser(u, env) });
      }

      if (pathname === '/me') {
        const u = await currentUser(req, env);
        if (!u) return json(req, { error: 'Session expirée, reconnecte-toi.' }, 401);
        return json(req, publicUser(u, env));
      }

      if (pathname === '/cart' && req.method === 'PUT') {
        const u = await currentUser(req, env);
        if (!u) return json(req, { error: 'Session expirée, reconnecte-toi.' }, 401);
        const body = await req.text();
        if (body.length > 30000) return json(req, { error: 'Panier trop grand.' }, 413);
        const { cart } = JSON.parse(body);
        if (!Array.isArray(cart)) return json(req, { error: 'Panier invalide.' }, 400);
        await env.DB.prepare('UPDATE users SET cart = ? WHERE id = ?').bind(JSON.stringify(cart.slice(0, 50)), u.id).run();
        return json(req, { ok: true });
      }

      if (pathname === '/logout' && req.method === 'POST') {
        const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/, '');
        if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
        return json(req, { ok: true });
      }

      return json(req, { error: 'Introuvable.' }, 404);
    } catch (x) {
      return json(req, { error: 'Erreur du serveur, réessaie dans un instant.' }, 500);
    }
  }
};
