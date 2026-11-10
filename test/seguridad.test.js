// Pruebas de seguridad de la API.
//
// Es la versión 2 del primer archivo de seguridad. Contiene:
//   - Lo mismo que ya probábamos antes (tokens, límite de intentos, contraseñas, SQL injection,
//     entradas hostiles, secretos en la base), adaptado al flujo actual: AHORA el registro no
//     entrega sesión directamente, hay que verificar el correo y activar el 2FA primero (por eso
//     se usa `registerWithMfa` en vez de leer `accessToken` del registro).
//   - Pruebas NUEVAS para lo que agregó el equipo después (metas, reportes, 2FA) y para huecos
//     que no se habían probado: aislamiento entre usuarios en metas, manipulación de tokens de
//     ingesta, fuerza bruta del código MFA pidiendo tokens nuevos, cabeceras de seguridad (Helmet),
//     CORS, límites de paginación y una prueba de tiempos de respuesta (orientativa, no concluyente).
//
// Cada prueba dice qué ataque o error simula y por qué importa. Si una falla, el mensaje indica
// qué caso fue. Las marcadas `todo` son hallazgos para decidir con el equipo, no bugs claros:
// se ejecutan y muestran el resultado, pero no rompen `npm test`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../src/config.js';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { registerWithMfa, totpFor, mailer } from './helpers.js';

const PW = 'una-clave-larga-123';

const parse = (text) => {
  if (!text) return null;
  try { return JSON.parse(text); } catch { return text; }
};

// Cambia un carácter del medio (no el último: en base64 a veces no altera los bytes reales).
const tamper = (s) => {
  const i = Math.floor(s.length / 2);
  return s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);
};
const wrongCode = (code) => String((Number(code) + 1) % 1e6).padStart(6, '0');

async function boot(extraEnv = {}) {
  const env = { PEPPER: 'a'.repeat(64), SCRYPT_N: '1024', AUTH_RATE_MAX: '1000', EMAIL_RESEND_COOLDOWN_SEC: '0', ...extraEnv };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gastos-seg-'));
  const db = openDb(path.join(dir, 'test.db'));
  // El mailer falso guarda los códigos de verificación: sin él, registerWithMfa no puede
  // leer el código del correo y el registro nunca se completa.
  const app = createApp(db, loadConfig(env), { mailer });
  const server = await new Promise((ok) => { const x = app.listen(0, () => ok(x)); });
  const base = `http://127.0.0.1:${server.address().port}`;

  const raw = async (method, url, { headers = {}, body } = {}) => {
    const res = await fetch(base + url, { method, headers, body });
    const text = await res.text();
    return { status: res.status, headers: res.headers, contentType: res.headers.get('content-type') || '', text, body: parse(text) };
  };
  const api = (method, url, body, token) => raw(method, url, {
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body !== undefined && body !== null ? JSON.stringify(body) : undefined,
  });
  const stop = () => { server.closeAllConnections?.(); server.close(); db.close(); fs.rmSync(dir, { recursive: true, force: true }); };
  return { api, raw, db, stop };
}

let s;
before(async () => { s = await boot(); });
after(() => s.stop());

// ===========================================================================
// 1. TOKENS
// ===========================================================================
test('tokens: sin token, vacío, sin Bearer o con basura dan 401 (nunca 500)', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'tok-basura@test.com');

  const casos = {
    'sin encabezado': {},
    'Bearer vacío': { Authorization: 'Bearer ' },
    'solo la palabra Bearer': { Authorization: 'Bearer' },
    'token sin prefijo Bearer': { Authorization: t },
    'esquema Basic': { Authorization: 'Basic ' + Buffer.from('a:b').toString('base64') },
    'basura': { Authorization: 'Bearer esto-no-es-un-token' },
    'puntos sueltos': { Authorization: 'Bearer ....' },
    'caracteres raros': { Authorization: 'Bearer %%%%@@@@' },
  };
  for (const [nombre, headers] of Object.entries(casos)) {
    const r = await s.raw('GET', '/v1/transactions', { headers });
    assert.equal(r.status, 401, `caso "${nombre}" devolvió ${r.status}`);
  }
});

test('tokens: un accessToken alterado es rechazado', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'tok-alterado@test.com');
  assert.equal((await s.api('GET', '/v1/transactions', null, tamper(t))).status, 401);
});

test('tokens: refreshToken no sirve como accessToken ni al revés', async () => {
  const reg = await registerWithMfa(s.api, 'tok-cruzado@test.com');
  assert.equal((await s.api('GET', '/v1/transactions', null, reg.refreshToken)).status, 401, 'el refreshToken no debería dar acceso a la API');
  assert.equal((await s.api('POST', '/v1/auth/refresh', { refreshToken: reg.accessToken })).status, 401, 'el accessToken no debería servir para refrescar');
});

test('tokens: un mfaToken no sirve como sesión ni se puede usar dos veces', async () => {
  const reg = await registerWithMfa(s.api, 'tok-mfa@test.com');
  const l = await s.api('POST', '/v1/auth/login', { email: 'tok-mfa@test.com', password: PW });
  assert.equal((await s.api('GET', '/v1/transactions', null, l.body.mfaToken)).status, 401, 'el mfaToken no debe abrir rutas protegidas');

  const code = totpFor(reg.totpSecret, 1);
  await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code });
  const reuso = await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code });
  assert.equal(reuso.status, 401, 'el mfaToken debe ser de un solo uso');
});

test('tokens: el token de ingesta no sirve en ninguna ruta salvo /v1/ingest', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'ingesta-limitada@test.com');
  const it = (await s.api('POST', '/v1/ingest-tokens', { label: 'tel' }, t)).body.token;

  const rutas = [
    ['GET', '/v1/transactions', null],
    ['GET', '/v1/transactions/summary', null],
    ['GET', '/v1/goals', null],
    ['GET', '/v1/goals/progress', null],
    ['GET', '/v1/reports/daily', null],
    ['GET', '/v1/ingest-tokens', null],
    ['POST', '/v1/ingest-tokens', { label: 'x' }],
    ['POST', '/v1/auth/change-password', { currentPassword: 'x', newPassword: 'y'.repeat(12) }],
    ['POST', '/v1/auth/logout', {}],
  ];
  for (const [m, u, body] of rutas) {
    const r = await s.api(m, u, body, it);
    assert.equal(r.status, 401, `${m} ${u} aceptó un token de ingesta (${r.status})`);
  }
});

test('tokens: un token de ingesta manipulado (secreto ajeno o sin secreto) es rechazado', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'ingesta-manipulada@test.com');
  const tok = (await s.api('POST', '/v1/ingest-tokens', { label: 'x' }, t)).body.token;
  const [id, secret] = tok.split('.');

  const r1 = await s.api('POST', '/v1/ingest', { merchant: 'x', amount: 1 }, `${id}.${'z'.repeat(secret.length)}`);
  assert.equal(r1.status, 401, 'un secreto ajeno (con el id correcto) no debería servir');

  const r2 = await s.api('POST', '/v1/ingest', { merchant: 'x', amount: 1 }, id);
  assert.equal(r2.status, 401, 'el token sin la parte del secreto no debería servir');

  // El token de ingesta de OTRO usuario, alterado, tampoco debe funcionar.
  const otro = await registerWithMfa(s.api, 'ingesta-ajeno@test.com');
  const tokOtro = (await s.api('POST', '/v1/ingest-tokens', { label: 'y' }, otro.accessToken)).body.token;
  const r3 = await s.api('POST', '/v1/ingest', { merchant: 'x', amount: 1 }, tamper(tokOtro));
  assert.equal(r3.status, 401);
});

// ===========================================================================
// 2. LÍMITE DE INTENTOS DE LOGIN (fuerza bruta sobre la contraseña)
// ===========================================================================
test('rate limit: tras varios intentos fallidos el login se bloquea (429)', async () => {
  const limited = await boot({ AUTH_RATE_MAX: '3' });
  try {
    await limited.api('POST', '/v1/auth/register', { email: 'bruteforce@test.com', password: 'clave-correcta-123' });
    const estados = [];
    for (let i = 0; i < 4; i++) {
      const r = await limited.api('POST', '/v1/auth/login', { email: 'bruteforce@test.com', password: `incorrecta-${i}-xxxxxx` });
      estados.push(r.status);
    }
    assert.ok(estados.every((c) => c < 500), `hubo errores 500: ${estados}`);
    assert.ok(estados.includes(429), `nunca se bloqueó. Estados: ${estados.join(', ')}`);

    const despues = await limited.api('POST', '/v1/auth/login', { email: 'bruteforce@test.com', password: 'clave-correcta-123' });
    assert.equal(despues.status, 429, 'bloqueado, pero la clave correcta sí entró');
  } finally {
    limited.stop();
  }
});

test('rate limit: el cupo se comparte entre registro, login y verificación de MFA (mismo IP)', async () => {
  // Confirmación de comportamiento (y nota para el equipo), no un fallo: cualquier petición a
  // /v1/auth/* (registrarse, loguearse, verificar el código...) gasta el MISMO cupo de 15 minutos.
  // Es bueno contra fuerza bruta, pero en una red con IP compartida (oficina, universidad, NAT
  // de un celular) los registros de unos pueden agotar el cupo de login de otros. Conviene
  // tenerlo en cuenta al elegir AUTH_RATE_MAX en producción.
  const limited = await boot({ AUTH_RATE_MAX: '5' });
  try {
    for (let i = 0; i < 3; i++) {
      const r = await limited.api('POST', '/v1/auth/register', { email: `cupo${i}@test.com`, password: PW });
      assert.equal(r.status, 201);
    }
    const l1 = await limited.api('POST', '/v1/auth/login', { email: 'nadie@test.com', password: 'x'.repeat(12) });
    assert.equal(l1.status, 401);
    const l2 = await limited.api('POST', '/v1/auth/login', { email: 'nadie@test.com', password: 'x'.repeat(12) });
    assert.equal(l2.status, 401);
    // Van 5 peticiones (3 registros + 2 logins): la sexta, sea cual sea, debe bloquearse.
    const l3 = await limited.api('POST', '/v1/auth/login', { email: 'nadie@test.com', password: 'x'.repeat(12) });
    assert.equal(l3.status, 429, 'el cupo no se compartió como se esperaba entre /register y /login');
  } finally {
    limited.stop();
  }
});

// ===========================================================================
// 3. FUERZA BRUTA SOBRE EL CÓDIGO MFA (pidiendo tokens nuevos)
// ===========================================================================
test('MFA: 5 intentos fallidos anulan el mfaToken, pero un login nuevo da otro con su propio tope', async () => {
  const reg = await registerWithMfa(s.api, 'mfa-reset@test.com');
  const l1 = await s.api('POST', '/v1/auth/login', { email: 'mfa-reset@test.com', password: PW });
  const t1 = l1.body.mfaToken;
  for (let i = 0; i < 5; i++) {
    const r = await s.api('POST', '/v1/auth/login/mfa', { mfaToken: t1, code: wrongCode(totpFor(reg.totpSecret, 1)) });
    assert.equal(r.status, 401, `intento ${i + 1} sobre el primer mfaToken devolvió ${r.status}`);
  }
  const vencido = await s.api('POST', '/v1/auth/login/mfa', { mfaToken: t1, code: totpFor(reg.totpSecret, 1) });
  assert.equal(vencido.status, 401, 'tras 5 fallos el mfaToken debía estar anulado, incluso con el código bueno');

  // Un login nuevo da un mfaToken DISTINTO, y ese nuevo token puede fallar otras 5 veces: el
  // conteo de intentos es por token, no por cuenta. Lo único que limita el total de códigos a
  // adivinar es el límite de peticiones por IP (ver la prueba siguiente).
  const l2 = await s.api('POST', '/v1/auth/login', { email: 'mfa-reset@test.com', password: PW });
  assert.notEqual(l2.body.mfaToken, t1, 'el login nuevo debería dar un mfaToken distinto');
  const r = await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l2.body.mfaToken, code: wrongCode(totpFor(reg.totpSecret, 1)) });
  assert.equal(r.status, 401, 'primer intento del segundo token');
  const ok = await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l2.body.mfaToken, code: totpFor(reg.totpSecret, 1) });
  assert.equal(ok.status, 200, 'el código bueno en el segundo token (tras solo 1 fallo) debía funcionar');
});

test('MFA: el total de intentos queda acotado por el límite de peticiones, no es ilimitado', async () => {
  // Con un cupo bajo de peticiones por IP, un atacante no puede pedir mfaTokens nuevos sin
  // parar: en algún punto el límite de 15 minutos lo detiene, aunque cada token individual
  // solo tenga 5 intentos.
  const limited = await boot({ AUTH_RATE_MAX: '6' });
  try {
    const reg = await registerWithMfa(limited.api, 'mfa-acotado@test.com'); // gasta 4 peticiones
    let bloqueado = false;
    for (let ronda = 0; ronda < 5 && !bloqueado; ronda++) {
      const l = await limited.api('POST', '/v1/auth/login', { email: 'mfa-acotado@test.com', password: PW });
      if (l.status === 429) { bloqueado = true; break; }
      const r = await limited.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code: wrongCode(totpFor(reg.totpSecret, ronda + 1)) });
      if (r.status === 429) bloqueado = true;
    }
    assert.ok(bloqueado, 'tras varias rondas de login + intento fallido, el límite de peticiones nunca actuó');
  } finally {
    limited.stop();
  }
});

// ===========================================================================
// 4. CONTRASEÑAS Y CORREOS
// ===========================================================================
test('registro: contraseñas inválidas (cortas o de tipo incorrecto) dan 400', async () => {
  const malas = ['', '1', '123456', 'corta', null, 12345678901234, ['a'], {}];
  for (const [i, password] of malas.entries()) {
    const r = await s.api('POST', '/v1/auth/register', { email: `debil${i}@test.com`, password });
    assert.equal(r.status, 400, `contraseña ${JSON.stringify(password)} devolvió ${r.status}`);
  }
});

test('registro: correos inválidos dan 400', async () => {
  const malos = ['', 'noesmail', '@test.com', 'a@', 'a b@test.com', null, 123, ['a@test.com'], {}];
  for (const email of malos) {
    const r = await s.api('POST', '/v1/auth/register', { email, password: PW });
    assert.equal(r.status, 400, `email ${JSON.stringify(email)} devolvió ${r.status}`);
  }
});

test('registro y login: cuerpo vacío o campos faltantes dan 400/401, no 500', async () => {
  for (const url of ['/v1/auth/register', '/v1/auth/login']) {
    for (const body of [{}, { email: 'a@test.com' }, { password: PW }]) {
      const r = await s.api('POST', url, body);
      assert.ok([400, 401].includes(r.status), `${url} ${JSON.stringify(body)} devolvió ${r.status}`);
    }
  }
});

// ===========================================================================
// 5. INYECCIÓN SQL
// ===========================================================================
test('SQL injection: el texto malicioso se guarda tal cual en una transacción y las tablas siguen ahí', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'sqli@test.com');
  const payload = "'; DROP TABLE transactions;--";

  const c = await s.api('POST', '/v1/transactions', { merchant: payload, description: payload, amount: 10 }, t);
  assert.equal(c.status, 201);
  const r = await s.api('GET', `/v1/transactions/${c.body.id}`, null, t);
  assert.equal(r.status, 200);
  assert.equal(r.body.merchant, payload);

  for (const tabla of ['transactions', 'users', 'credentials']) {
    assert.ok(s.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(tabla), `falta la tabla ${tabla}`);
  }
});

test('SQL injection: filtros de la URL y login no se dejan manipular', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'sqli-filtros@test.com');
  await s.api('POST', '/v1/transactions', { merchant: 'normal', amount: 5, type: 'cash' }, t);

  const filtros = { type: "' OR 1=1--", status: "x'; DROP TABLE transactions;--", category: "y' UNION SELECT * FROM users--" };
  for (const [k, v] of Object.entries(filtros)) {
    const r = await s.api('GET', `/v1/transactions?${k}=${encodeURIComponent(v)}`, null, t);
    assert.ok(r.status < 500, `filtro ${k}="${v}" causó ${r.status}`);
  }

  const login = await s.api('POST', '/v1/auth/login', { email: "' OR '1'='1", password: "' OR '1'='1" });
  assert.ok([400, 401].includes(login.status), `login con SQLi devolvió ${login.status}`);
  assert.ok(s.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").get());
});

test('SQL injection y XSS en metas: se guardan como texto y la tabla goals sigue ahí', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'sqli-goals@test.com');
  const sqli = "'; DROP TABLE goals;--";
  const r1 = await s.api('POST', '/v1/goals', { category: sqli, limit: 1000 }, t);
  assert.equal(r1.status, 201);
  assert.equal(r1.body.category, sqli);

  const xss = '<script>alert(1)</script>';
  const r2 = await s.api('POST', '/v1/goals', { category: xss, limit: 1000 }, t);
  assert.equal(r2.status, 201);
  assert.equal(r2.body.category, xss, 'el texto no debe alterarse al guardarlo o devolverlo');

  assert.ok(s.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='goals'").get());
});

// ===========================================================================
// 6. ENTRADAS HOSTILES
// ===========================================================================
test('JSON roto o con Content-Type raro responde 400/415, no 500', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'json-roto@test.com');
  const auth = { Authorization: `Bearer ${t}` };

  const roto = await s.raw('POST', '/v1/transactions', { headers: { ...auth, 'Content-Type': 'application/json' }, body: '{"merchant": "x", "amount":' });
  assert.equal(roto.status, 400, `JSON roto devolvió ${roto.status}`);

  const texto = await s.raw('POST', '/v1/transactions', { headers: { ...auth, 'Content-Type': 'text/plain' }, body: 'hola' });
  assert.ok([400, 415].includes(texto.status), `text/plain devolvió ${texto.status}`);

  const array = await s.api('POST', '/v1/transactions', [1, 2, 3], t);
  assert.equal(array.status, 400, `cuerpo tipo array devolvió ${array.status}`);

  const nulo = await s.raw('POST', '/v1/transactions', { headers: { ...auth, 'Content-Type': 'application/json' }, body: 'null' });
  assert.equal(nulo.status, 400, `cuerpo null devolvió ${nulo.status}`);
});

test('tipos equivocados en los campos de una transacción dan 400, no 500', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'tipos@test.com');
  const casos = [
    { merchant: 123, amount: 10 }, { merchant: ['a'], amount: 10 }, { merchant: { a: 1 }, amount: 10 },
    { merchant: 'ok', amount: {} }, { merchant: 'ok', amount: [5] }, { merchant: 'ok', amount: true },
    { merchant: 'ok', amount: null }, { merchant: 'ok', amount: 10, type: 'inventado' }, { merchant: 'ok', amount: 10, status: 'inventado' },
  ];
  for (const body of casos) {
    const r = await s.api('POST', '/v1/transactions', body, t);
    assert.equal(r.status, 400, `${JSON.stringify(body)} devolvió ${r.status}`);
  }
});

test('metas: límites de monto y de longitud de categoría dan 400; una meta duplicada da 409', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'limites-metas@test.com');
  assert.equal((await s.api('POST', '/v1/goals', { category: 'x'.repeat(61), limit: 1000 }, t)).status, 400, 'categoría de 61 caracteres');
  assert.equal((await s.api('POST', '/v1/goals', { category: 'a', limit: -100 }, t)).status, 400, 'límite negativo');
  assert.equal((await s.api('POST', '/v1/goals', { category: 'b', limit: 0 }, t)).status, 400, 'límite en cero');
  assert.equal((await s.api('POST', '/v1/goals', { category: 'c', limit: 'x' }, t)).status, 400, 'límite no numérico');

  const ok = await s.api('POST', '/v1/goals', { category: 'comida', limit: 50000 }, t);
  assert.equal(ok.status, 201);
  const dup = await s.api('POST', '/v1/goals', { category: 'comida', limit: 10000 }, t);
  assert.equal(dup.status, 409, 'no debería permitir dos metas para la misma categoría');
});

test('texto gigante (1 MB) se rechaza y el servidor sigue vivo', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'gigante@test.com');
  let status;
  try {
    status = (await s.api('POST', '/v1/transactions', { merchant: 'x', amount: 1, description: 'a'.repeat(1_000_000) }, t)).status;
  } catch {
    // El servidor puede cortar la conexión al ver Content-Length > 20 kb, antes de que el
    // cliente termine de enviar: también es un rechazo válido. Lo que importa es que siga vivo.
    status = 'conexión cortada';
  }
  assert.ok([400, 413, 'conexión cortada'].includes(status), `1 MB en description devolvió ${status}`);
  const vivo = await s.api('GET', '/v1/transactions', null, t);
  assert.equal(vivo.status, 200, 'el servidor dejó de responder tras la entrada gigante');
});

test('emojis, acentos y caracteres especiales se guardan y leen idénticos', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'unicode@test.com');
  const datos = { merchant: 'Café ñandú 🍕 日本語', description: 'línea 1\nlínea 2\t"comillas" \\ barra <b>html</b>', category: 'Comida 🍔' };
  const c = await s.api('POST', '/v1/transactions', { ...datos, amount: 7000 }, t);
  assert.equal(c.status, 201);
  const r = await s.api('GET', `/v1/transactions/${c.body.id}`, null, t);
  assert.equal(r.body.merchant, datos.merchant);
  assert.equal(r.body.description, datos.description);
  assert.equal(r.body.category, datos.category);
});

test('XSS almacenado: el texto no se altera y la respuesta es JSON', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'xss@test.com');
  const xss = '<script>alert(1)</script>';
  const c = await s.api('POST', '/v1/transactions', { merchant: xss, amount: 1 }, t);
  assert.equal(c.status, 201);
  const r = await s.api('GET', `/v1/transactions/${c.body.id}`, null, t);
  assert.equal(r.body.merchant, xss);
  assert.match(r.headers.get('content-type') || '', /application\/json/);
});

test('IDs raros en la URL dan 400/404, no 500 (transacciones y metas)', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'ids@test.com');
  const raros = ['abc', '-1', '0', '999999999999', "1'OR'1'='1", '%00', '../../etc/passwd'];
  for (const id of raros) {
    const r = await s.api('GET', `/v1/transactions/${encodeURIComponent(id)}`, null, t);
    assert.ok([400, 404].includes(r.status), `GET transacción con id "${id}" devolvió ${r.status}`);
    const d = await s.api('DELETE', `/v1/goals/${encodeURIComponent(id)}`, null, t);
    assert.ok([400, 404].includes(d.status), `DELETE meta con id "${id}" devolvió ${d.status}`);
  }
});

test('transacciones: límites de paginación inválidos dan 400, no 500', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'paginacion@test.com');
  for (const qs of ['limit=0', 'limit=201', 'offset=-1', 'limit=abc', 'limit=-5']) {
    const r = await s.api('GET', `/v1/transactions?${qs}`, null, t);
    assert.equal(r.status, 400, `?${qs} devolvió ${r.status}`);
  }
});

test('reportes: rangos de fechas y parámetros inválidos dan 400, no 500', async () => {
  const { accessToken: t } = await registerWithMfa(s.api, 'reportes-limites@test.com');
  assert.equal((await s.api('GET', '/v1/reports/daily?from=2020-01-01&to=2026-12-31', null, t)).status, 400, 'rango de más de 366 días');
  assert.equal((await s.api('GET', '/v1/reports/daily?from=2026-01-10&to=2026-01-01', null, t)).status, 400, 'from posterior a to');
  assert.equal((await s.api('GET', '/v1/reports/daily?tz=Foo/Bar', null, t)).status, 400, 'zona horaria inválida');
  assert.equal((await s.api('GET', '/v1/reports/weekly?weeks=0', null, t)).status, 400, 'weeks en cero');
  assert.equal((await s.api('GET', '/v1/reports/weekly?weeks=999', null, t)).status, 400, 'weeks fuera de rango');
});

// ===========================================================================
// 7. AISLAMIENTO ENTRE USUARIOS (IDOR) EN METAS Y REPORTES
// ===========================================================================
test('aislamiento: nadie ve, edita ni borra las metas de otro usuario', async () => {
  const a = await registerWithMfa(s.api, 'meta-a@test.com');
  const b = await registerWithMfa(s.api, 'meta-b@test.com');
  const g = await s.api('POST', '/v1/goals', { category: 'comida', limit: 50000 }, a.accessToken);
  assert.equal(g.status, 201);

  assert.equal((await s.api('PATCH', `/v1/goals/${g.body.id}`, { limit: 1 }, b.accessToken)).status, 404);
  assert.equal((await s.api('DELETE', `/v1/goals/${g.body.id}`, null, b.accessToken)).status, 404);
  assert.deepEqual((await s.api('GET', '/v1/goals', null, b.accessToken)).body, []);

  // La meta de A debe seguir intacta después del intento de B.
  const sigue = await s.api('GET', '/v1/goals', null, a.accessToken);
  assert.equal(sigue.body.length, 1);
  assert.equal(sigue.body[0].limit, 50000, 'el intento de B no debió alcanzar a modificarla');
});

test('aislamiento: los reportes de un usuario no incluyen gastos de otro', async () => {
  const a = await registerWithMfa(s.api, 'rep-a@test.com');
  const b = await registerWithMfa(s.api, 'rep-b@test.com');
  await s.api('POST', '/v1/transactions', { merchant: 'Secreto de A', amount: 999000, category: 'comida' }, a.accessToken);

  const repB = await s.api('GET', '/v1/reports/daily', null, b.accessToken);
  assert.equal(repB.body.summary.total, 0, 'el reporte de B no debería ver el gasto de A');
  const progB = await s.api('GET', '/v1/goals/progress', null, b.accessToken);
  assert.deepEqual(progB.body.goals, []);
});

// ===========================================================================
// 8. SECRETOS EN LA BASE DE DATOS
// ===========================================================================
test('los tokens, la llave de recuperación y el secreto del Authenticator no quedan en claro en la base', async () => {
  const reg = await registerWithMfa(s.api, 'token-en-claro@test.com');
  s.db.pragma('wal_checkpoint(TRUNCATE)');

  // JSON.stringify convierte los BLOB en listas de números y ocultaría cualquier texto en claro,
  // así que cada valor binario se pasa a texto (latin1) antes de buscar.
  const texto = (rows) => rows.map((row) => Object.values(row)
    .map((v) => (Buffer.isBuffer(v) ? v.toString('latin1') : String(v))).join('|')).join('\n');
  const dump = texto(s.db.prepare('SELECT * FROM users').all()) + texto(s.db.prepare('SELECT * FROM credentials').all());

  const secretosDe = (token) => token.split('.'); // [id, secreto]
  for (const [nombre, secreto] of [
    ['secreto del accessToken', secretosDe(reg.accessToken)[1]],
    ['secreto del refreshToken', secretosDe(reg.refreshToken)[1]],
    ['recoveryKey', reg.recoveryKey],
    ['recoveryKey sin guiones', reg.recoveryKey.replace(/-/g, '')],
    ['secreto TOTP (base32)', reg.totpSecret],
  ]) {
    assert.ok(!dump.includes(secreto), `${nombre} aparece en claro en la base`);
  }
});

// ===========================================================================
// 9. CABECERAS DE SEGURIDAD (Helmet)
// ===========================================================================
test('cabeceras de seguridad: Helmet está activo y no se expone x-powered-by', async () => {
  const r = await s.raw('GET', '/health');
  assert.equal(r.headers.get('x-powered-by'), null, 'no debería anunciar que usa Express');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.match(r.headers.get('strict-transport-security') || '', /max-age=\d+/);
  assert.ok(r.headers.get('content-security-policy'), 'falta Content-Security-Policy');
});

// ===========================================================================
// 10. CORS
// ===========================================================================
test('CORS: sin CORS_ORIGINS configurado, un origen externo no recibe permiso', async () => {
  const r = await s.raw('OPTIONS', '/v1/auth/login', {
    headers: { Origin: 'https://sitio-malicioso.example', 'Access-Control-Request-Method': 'POST' },
  });
  const acao = r.headers.get('access-control-allow-origin');
  assert.ok(!acao || acao === 'null', `un origen no autorizado recibió "${acao}"`);
});

test('CORS: con CORS_ORIGINS=* el servidor refleja cualquier origen (confirmación de la configuración)', async () => {
  // No es un error: es como queda configurado el servidor si alguien pone "*" en CORS_ORIGINS.
  // Como la API usa Bearer tokens (no cookies), el riesgo es menor que con sesiones por cookie,
  // pero "*" abre la API a cualquier sitio web, no solo a la app oficial.
  const open = await boot({ CORS_ORIGINS: '*' });
  try {
    const r = await open.raw('OPTIONS', '/v1/auth/login', {
      headers: { Origin: 'https://cualquier-sitio.example', 'Access-Control-Request-Method': 'POST' },
    });
    assert.equal(r.headers.get('access-control-allow-origin'), 'https://cualquier-sitio.example');
  } finally {
    open.stop();
  }
});

// ===========================================================================
// 11. TIEMPOS DE RESPUESTA (orientativo, no concluyente: los tiempos varían según la máquina)
// ===========================================================================
test('login: el tiempo de respuesta no debería delatar claramente si el correo existe',
  { todo: 'Prueba orientativa de timing; sensible al entorno, no usar como única evidencia' }, async () => {
  await registerWithMfa(s.api, 'timing@test.com');
  const tiempo = async (email) => {
    const ini = performance.now();
    await s.api('POST', '/v1/auth/login', { email, password: 'cualquiera-123456' });
    return performance.now() - ini;
  };
  const existente = [];
  const inexistente = [];
  for (let i = 0; i < 15; i++) {
    existente.push(await tiempo('timing@test.com'));
    inexistente.push(await tiempo(`no-existe-${i}@test.com`));
  }
  const avg = (arr) => arr.reduce((a, b) => a + b, 0) / arr.length;
  const diff = Math.abs(avg(existente) - avg(inexistente));
  assert.ok(diff < 15, `diferencia promedio de ${diff.toFixed(1)} ms entre correo existente e inexistente (revisar si crece en otra máquina)`);
});