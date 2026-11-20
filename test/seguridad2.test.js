// PEDIDO DE PRUEBAS (José) · Sección 2: seguridad con lo que ya existe (S-01 a S-07).
//
// Cada prueba lleva el ID del pedido y el requisito que cubre (RNF-03, RNF-05, RNF-06) para citarla
// en la matriz de pruebas. Todo corre en local: servidor en memoria, base PGlite temporal y mailer
// falso (no se envía ningún correo real).
//
//   node --test test/pedido-seguridad.test.js

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';
import { base32Decode, totpCode } from '../src/totp.js';
import { registerWithMfa, mailer, openTestDb } from './helpers.js';

const PW = 'una-clave-larga-123';
const wrongCode = (code) => String((Number(code) + 1) % 1e6).padStart(6, '0');

/**
 * Levanta la API en un puerto libre. `api(..., { ip })` permite simular la dirección de origen con
 * X-Forwarded-For (solo tiene efecto si TRUST_PROXY=1, como detrás del balanceador de AWS).
 */
async function boot(extraEnv = {}) {
  const env = { PEPPER: 'b'.repeat(64), SCRYPT_N: '1024', AUTH_RATE_MAX: '1000', EMAIL_RESEND_COOLDOWN_SEC: '0', ...extraEnv };
  const { db, close } = await openTestDb('gastos-pedido-seg-');
  const app = createApp(db, loadConfig(env), { mailer });
  const server = await new Promise((ok) => { const x = app.listen(0, () => ok(x)); });
  const base = `http://127.0.0.1:${server.address().port}`;

  const api = async (method, url, body, token, { ip } = {}) => {
    const res = await fetch(base + url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(ip ? { 'X-Forwarded-For': ip } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : null };
  };
  const register = (email) => registerWithMfa(api, email, PW);
  const stop = async () => { server.closeAllConnections?.(); server.close(); await close(); };
  return { api, register, db, stop };
}

let s;
before(async () => { s = await boot(); });
after(() => s.stop());

// ===========================================================================
// S-01 · Aislamiento entre usuarios (RNF-03)
// ===========================================================================
test('S-01 el usuario B pide, edita o borra un gasto del usuario A: 404 (como si no existiera)', async () => {
  const a = await s.register('s01-a@test.com');
  const b = await s.register('s01-b@test.com');
  const gastoA = (await s.api('POST', '/v1/transactions', { merchant: 'Gasto-de-A', amount: 50000, category: 'privada' }, a.accessToken)).body;

  const inexistente = '00000000-0000-4000-8000-000000000000';
  const noExiste = await s.api('GET', `/v1/transactions/${inexistente}`, null, b.accessToken);
  assert.equal(noExiste.status, 404);

  for (const [m, body] of [['GET'], ['PATCH', { amount: 1 }], ['DELETE']]) {
    const r = await s.api(m, `/v1/transactions/${gastoA.id}`, body, b.accessToken);
    assert.equal(r.status, 404, `${m} del gasto de A con la sesión de B`);
    assert.deepEqual(r.body, noExiste.body, `${m}: la respuesta debe ser idéntica a la de un id inexistente`);
  }

  // B tampoco lo ve en sus listados ni en sus reportes.
  const lista = await s.api('GET', '/v1/transactions', null, b.accessToken);
  assert.equal(lista.body.total, 0);
  assert.ok(!JSON.stringify(lista.body).includes('Gasto-de-A'));
  assert.equal((await s.api('GET', '/v1/transactions/summary', null, b.accessToken)).body.total, 0);
  assert.equal((await s.api('GET', '/v1/reports/daily', null, b.accessToken)).body.summary.total, 0);

  // El gasto de A sigue intacto (B no lo cambió ni lo borró).
  const sigue = await s.api('GET', `/v1/transactions/${gastoA.id}`, null, a.accessToken);
  assert.equal(sigue.status, 200);
  assert.deepEqual([sigue.body.merchant, sigue.body.amount, sigue.body.category], ['Gasto-de-A', 50000, 'privada']);
});

test('S-01b el usuario B edita o borra una meta del usuario A: 404 (como si no existiera)', async () => {
  const a = await s.register('s01b-a@test.com');
  const b = await s.register('s01b-b@test.com');
  const metaA = (await s.api('POST', '/v1/goals', { category: 'comida', limit: 300000 }, a.accessToken)).body;

  const noExiste = await s.api('PATCH', '/v1/goals/00000000-0000-4000-8000-000000000000', { limit: 1 }, b.accessToken);
  assert.equal(noExiste.status, 404);

  // Las metas no tienen GET /:id; se prueban las rutas que sí reciben un id.
  for (const [m, body] of [['PATCH', { limit: 1 }], ['PATCH', { category: 'otra' }], ['DELETE']]) {
    const r = await s.api(m, `/v1/goals/${metaA.id}`, body, b.accessToken);
    assert.equal(r.status, 404, `${m} de la meta de A con la sesión de B`);
    assert.deepEqual(r.body, noExiste.body, `${m}: la respuesta debe ser idéntica a la de un id inexistente`);
  }

  assert.deepEqual((await s.api('GET', '/v1/goals', null, b.accessToken)).body, [], 'B no ve metas ajenas');
  assert.deepEqual((await s.api('GET', '/v1/goals/progress', null, b.accessToken)).body.goals, []);

  const metasA = (await s.api('GET', '/v1/goals', null, a.accessToken)).body;
  assert.deepEqual(metasA.map((g) => [g.id, g.category, g.limit]), [[metaA.id, 'comida', 300000]], 'la meta de A sigue intacta');
});

test('S-01c el usuario B no puede revocar el token de captura del usuario A: 404', async () => {
  const a = await s.register('s01c-a@test.com');
  const b = await s.register('s01c-b@test.com');
  const token = (await s.api('POST', '/v1/ingest-tokens', { label: 'iPhone A' }, a.accessToken)).body.token;
  const id = token.split('.')[0];

  assert.equal((await s.api('DELETE', `/v1/ingest-tokens/${id}`, null, b.accessToken)).status, 404);
  assert.deepEqual((await s.api('GET', '/v1/ingest-tokens', null, b.accessToken)).body, []);
  assert.equal((await s.api('POST', '/v1/ingest', { merchant: 'Sigue', amount: 1000 }, token)).status, 201, 'el token de A sigue sirviendo');
});

// ===========================================================================
// S-02 · Límite de intentos de login (RNF-05)
// ===========================================================================
test('S-02 21 intentos de login seguidos desde la misma dirección: 429 a partir del 21', async () => {
  // Servidor propio con el límite de producción (20 por IP cada 15 min) y detrás de un proxy,
  // para poder simular dos direcciones distintas: la de la víctima y la del atacante.
  const srv = await boot({ AUTH_RATE_MAX: '20', TRUST_PROXY: '1' });
  try {
    const email = 's02@test.com';
    // La víctima se registra desde su propia dirección (4 peticiones a /auth que cuentan para ESA IP).
    const victimaApi = (m, url, body, token) => srv.api(m, url, body, token, { ip: '10.0.0.1' });
    await registerWithMfa(victimaApi, email, PW);

    const ATACANTE = { ip: '10.0.0.66' };
    for (let i = 1; i <= 20; i++) {
      const r = await srv.api('POST', '/v1/auth/login', { email, password: `clave-mala-${i}-xx` }, null, ATACANTE);
      assert.equal(r.status, 401, `intento ${i}: aún dentro del límite, contraseña incorrecta`);
      assert.equal(r.headers.get('ratelimit-remaining'), String(20 - i), `intento ${i}: cabecera RateLimit-Remaining`);
    }

    const r21 = await srv.api('POST', '/v1/auth/login', { email, password: 'clave-mala-21-xx' }, null, ATACANTE);
    assert.equal(r21.status, 429, 'el intento 21 debe bloquearse');
    assert.match(r21.body.error, /Demasiados intentos/);
    assert.ok(r21.body.retryAfterSec > 0 && r21.body.retryAfterSec <= 15 * 60, 'indica cuánto esperar (máx. 15 min)');
    assert.equal(r21.headers.get('ratelimit-limit'), '20');

    // Bloqueado incluso con la contraseña correcta: el atacante no puede seguir probando.
    const r22 = await srv.api('POST', '/v1/auth/login', { email, password: PW }, null, ATACANTE);
    assert.equal(r22.status, 429, 'con la contraseña correcta también da 429');
    assert.equal(r22.body.mfaToken, undefined, 'no entrega mfaToken');

    // El límite aplica a todas las rutas de /auth desde esa dirección, no solo al login.
    assert.equal((await srv.api('POST', '/v1/auth/recover', { email, recoveryKey: 'x', newPassword: 'otra-clave-123' }, null, ATACANTE)).status, 429);

    // La víctima, desde su dirección, sigue pudiendo entrar (el bloqueo es por dirección, no por cuenta).
    const v = await srv.api('POST', '/v1/auth/login', { email, password: PW }, null, { ip: '10.0.0.1' });
    assert.equal(v.status, 200);
    assert.ok(v.body.mfaToken);
  } finally {
    await srv.stop();
  }
});

// ===========================================================================
// S-03 · El refreshToken es de un solo uso (RNF-06)
// ===========================================================================
test('S-03 reusar un refreshToken ya usado: 401', async () => {
  const reg = await s.register('s03@test.com');
  const r1 = await s.api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken });
  assert.equal(r1.status, 200);
  assert.notEqual(r1.body.refreshToken, reg.refreshToken, 'el refresh debe rotar');

  const reuso = await s.api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken });
  assert.equal(reuso.status, 401, 'el refreshToken ya usado no debe servir');
  assert.equal(reuso.body.accessToken, undefined);

  // Un tercer intento tampoco (no es un problema de tiempo), y el par nuevo sí funciona.
  assert.equal((await s.api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken })).status, 401);
  assert.equal((await s.api('GET', '/v1/transactions', null, r1.body.accessToken)).status, 200);
  const r2 = await s.api('POST', '/v1/auth/refresh', { refreshToken: r1.body.refreshToken });
  assert.equal(r2.status, 200);
  assert.equal((await s.api('POST', '/v1/auth/refresh', { refreshToken: r1.body.refreshToken })).status, 401, 'el segundo también es de un solo uso');
});

test('S-03b dos peticiones simultáneas con el mismo refreshToken: solo una debe obtener sesión',
  { todo: 'Posible hallazgo: /auth/refresh valida y revoca en dos pasos sin comprobar si la revocación aplicó; dos peticiones a la vez pueden pasar las dos' }, async () => {
  const reg = await s.register('s03b@test.com');
  const resultados = await Promise.all(Array.from({ length: 5 }, () =>
    s.api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken })));
  const ok = resultados.filter((r) => r.status === 200).length;
  assert.equal(ok, 1, `el mismo refreshToken entregó ${ok} sesiones`);
});

// ===========================================================================
// S-04 · Token de captura revocado
// ===========================================================================
test('S-04 token de captura revocado llama a /v1/ingest: 401', async () => {
  const u = await s.register('s04@test.com');
  const token = (await s.api('POST', '/v1/ingest-tokens', { label: 'iPhone S04' }, u.accessToken)).body.token;
  const id = token.split('.')[0];

  // Antes de revocar funciona.
  assert.equal((await s.api('POST', '/v1/ingest', { merchant: 'Antes', amount: 1000 }, token)).status, 201);

  assert.equal((await s.api('DELETE', `/v1/ingest-tokens/${id}`, null, u.accessToken)).status, 204);
  const r = await s.api('POST', '/v1/ingest', { merchant: 'Despues', amount: 2000 }, token);
  assert.equal(r.status, 401, 'un token revocado no debe crear gastos');

  // No se creó nada y el token ya no aparece en el perfil.
  const lista = (await s.api('GET', '/v1/transactions', null, u.accessToken)).body;
  assert.deepEqual(lista.items.map((t) => t.merchant), ['Antes']);
  assert.deepEqual((await s.api('GET', '/v1/ingest-tokens', null, u.accessToken)).body, []);
  // Revocarlo otra vez no lo "revive" ni da error raro.
  assert.equal((await s.api('DELETE', `/v1/ingest-tokens/${id}`, null, u.accessToken)).status, 204);
  assert.equal((await s.api('POST', '/v1/ingest', { merchant: 'Despues', amount: 2000 }, token)).status, 401);
});

test('S-04b revocar un token de captura no afecta a los otros del mismo usuario', async () => {
  const u = await s.register('s04b@test.com');
  const t1 = (await s.api('POST', '/v1/ingest-tokens', { label: 'iPhone' }, u.accessToken)).body.token;
  const t2 = (await s.api('POST', '/v1/ingest-tokens', { label: 'iPad' }, u.accessToken)).body.token;
  assert.equal((await s.api('DELETE', `/v1/ingest-tokens/${t1.split('.')[0]}`, null, u.accessToken)).status, 204);
  assert.equal((await s.api('POST', '/v1/ingest', { merchant: 'x', amount: 1 }, t1)).status, 401);
  assert.equal((await s.api('POST', '/v1/ingest', { merchant: 'y', amount: 1 }, t2)).status, 201);
});

// ===========================================================================
// S-05 · El token de captura solo puede crear gastos
// ===========================================================================
test('S-05 token de captura intenta leer gastos o cambiar la contraseña: rechazado (solo crea gastos)', async () => {
  const email = 's05@test.com';
  const u = await s.register(email);
  const token = (await s.api('POST', '/v1/ingest-tokens', { label: 'iPhone S05' }, u.accessToken)).body.token;
  const gasto = (await s.api('POST', '/v1/transactions', { merchant: 'Privado', amount: 1000 }, u.accessToken)).body;
  const meta = (await s.api('POST', '/v1/goals', { limit: 100000 }, u.accessToken)).body;

  const prohibidas = [
    ['GET', '/v1/transactions'],
    ['GET', '/v1/transactions/summary'],
    ['GET', `/v1/transactions/${gasto.id}`],
    ['PATCH', `/v1/transactions/${gasto.id}`, { amount: 1 }],
    ['DELETE', `/v1/transactions/${gasto.id}`],
    ['POST', '/v1/transactions', { merchant: 'Por la puerta de atrás', amount: 1 }],
    ['GET', '/v1/goals'],
    ['GET', '/v1/goals/progress'],
    ['PATCH', `/v1/goals/${meta.id}`, { limit: 1 }],
    ['DELETE', `/v1/goals/${meta.id}`],
    ['GET', '/v1/reports/daily'],
    ['GET', '/v1/reports/weekly'],
    ['GET', '/v1/ingest-tokens'],
    ['POST', '/v1/ingest-tokens', { label: 'otro token' }],
    ['POST', '/v1/auth/change-password', { currentPassword: PW, newPassword: 'clave-del-atacante-1' }],
    ['POST', '/v1/auth/logout', { all: true }],
    ['GET', '/v1/admin/users'],
  ];
  for (const [m, url, body] of prohibidas) {
    const r = await s.api(m, url, body, token);
    assert.equal(r.status, 401, `${m} ${url} con el token de captura`);
    assert.ok(!JSON.stringify(r.body).includes('Privado'), `${m} ${url}: no debe devolver datos`);
  }
  // Tampoco sirve como refreshToken.
  assert.equal((await s.api('POST', '/v1/auth/refresh', { refreshToken: token })).status, 401);

  // Nada cambió: la contraseña sigue siendo la misma, el gasto y la meta siguen iguales.
  const login = await s.api('POST', '/v1/auth/login', { email, password: PW });
  assert.equal(login.status, 200, 'la contraseña original sigue funcionando');
  assert.equal((await s.api('POST', '/v1/auth/login', { email, password: 'clave-del-atacante-1' })).status, 401);
  const lista = (await s.api('GET', '/v1/transactions', null, u.accessToken)).body;
  assert.deepEqual(lista.items.map((t) => [t.merchant, t.amount]), [['Privado', 1000]]);
  assert.equal((await s.api('GET', '/v1/goals', null, u.accessToken)).body[0].limit, 100000);

  // Lo único que sí puede hacer: crear gastos.
  const ok = await s.api('POST', '/v1/ingest', { merchant: 'Con Apple Pay', amount: '25.000' }, token);
  assert.equal(ok.status, 201);
  assert.deepEqual(Object.keys(ok.body), ['id'], 'la respuesta del ingest solo trae el id, no datos del usuario');
});

test('S-05b los tokens de sesión no sirven en /v1/ingest (cada token tiene su uso)', async () => {
  const u = await s.register('s05b@test.com');
  assert.equal((await s.api('POST', '/v1/ingest', { merchant: 'x', amount: 1 }, u.accessToken)).status, 401, 'accessToken');
  assert.equal((await s.api('POST', '/v1/ingest', { merchant: 'x', amount: 1 }, u.refreshToken)).status, 401, 'refreshToken');
});

// ===========================================================================
// S-06 · Código de correo incorrecto 6 veces
// ===========================================================================
test('S-06 código de correo incorrecto 6 veces: se anula a los 5 intentos', async () => {
  const email = 's06@test.com';
  const reg = await s.api('POST', '/v1/auth/register', { email, password: PW });
  assert.equal(reg.status, 201);
  const code = mailer.lastCode(email);
  assert.match(code, /^\d{6}$/);
  const verify = (c) => s.api('POST', '/v1/auth/verify-email', { email, code: c });

  for (let i = 1; i <= 5; i++) {
    const r = await verify(wrongCode(code));
    assert.equal(r.status, 401, `intento ${i}: código incorrecto`);
    assert.equal(r.body.attemptsLeft, 5 - i, `intento ${i}: intentos restantes`);
  }

  const sexto = await verify(wrongCode(code));
  assert.equal(sexto.status, 400, 'el 6.º intento ya no se evalúa');
  assert.match(sexto.body.error, /Demasiados intentos/);

  // El código correcto tampoco sirve ya: quedó anulado.
  const correcto = await verify(code);
  assert.equal(correcto.status, 400, 'tras 5 fallos, ni el código correcto verifica el correo');
  assert.match(correcto.body.error, /Demasiados intentos/);
  const fila = await s.db.get('SELECT email_verified_at, email_code_attempts FROM users WHERE id = $1', [reg.body.user.id]);
  assert.equal(fila.email_verified_at, null, 'el correo sigue sin verificar');
  assert.equal(fila.email_code_attempts, 5, 'no se siguen sumando intentos después del 5.º');

  // Sin correo verificado no se puede iniciar sesión.
  const login = await s.api('POST', '/v1/auth/login', { email, password: PW });
  assert.equal(login.status, 403);
  assert.equal(login.body.emailVerificationRequired, true);

  // La salida es pedir un código nuevo: el viejo sigue sin servir y el nuevo sí.
  assert.equal((await s.api('POST', '/v1/auth/resend-code', { email })).status, 200);
  const nuevo = mailer.lastCode(email);
  if (nuevo !== code) assert.equal((await verify(code)).status, 401, 'el código anterior no sirve');
  assert.equal((await verify(nuevo)).status, 200);
});

// ===========================================================================
// S-07 · Reusar el código del Authenticator en el mismo paso de 30 s
// ===========================================================================
test('S-07 reusar el mismo código del Authenticator en el mismo paso de 30 s: rechazado', async () => {
  const email = 's07@test.com';
  const u = await s.register(email);
  const secret = base32Decode(u.totpSecret);
  const codigoDelPaso = (step) => totpCode(secret, step);
  const login = async () => {
    const l = await s.api('POST', '/v1/auth/login', { email, password: PW });
    assert.equal(l.status, 200);
    assert.equal(l.body.mfaRequired, true);
    return l.body.mfaToken;
  };
  const mfa = (mfaToken, code) => s.api('POST', '/v1/auth/login/mfa', { mfaToken, code });

  // 1) El código con el que se confirmó el QR (registro) no sirve para entrar después.
  //    Se calcula para el paso exacto que quedó guardado, así la prueba no depende del reloj.
  const { totp_last_step: pasoRegistro } = await s.db.get('SELECT totp_last_step FROM users WHERE id = $1', [u.user.id]);
  const t1 = await login();
  const reusoRegistro = await mfa(t1, codigoDelPaso(pasoRegistro));
  assert.equal(reusoRegistro.status, 401, 'el código usado al confirmar el QR no debe servir otra vez');
  assert.equal(reusoRegistro.body.accessToken, undefined);

  // 2) El código del paso siguiente (dentro de la ventana de ±30 s) sí sirve una vez...
  const pasoNuevo = pasoRegistro + 1;
  const codigo = codigoDelPaso(pasoNuevo);
  const ok = await mfa(t1, codigo);
  assert.equal(ok.status, 200, 'un código nuevo debe aceptarse');
  assert.ok(ok.body.accessToken);

  // 3) ...pero el MISMO código, en un login nuevo y dentro del mismo paso, se rechaza.
  const t2 = await login();
  const reuso = await mfa(t2, codigo);
  assert.equal(reuso.status, 401, 'reusar el código en el mismo paso debe rechazarse');
  assert.match(reuso.body.error, /incorrecto/i);
  assert.equal(reuso.body.accessToken, undefined);

  // 4) Tampoco sirve un código de un paso ANTERIOR al último usado (aunque siga en la ventana).
  assert.equal((await mfa(t2, codigoDelPaso(pasoRegistro))).status, 401);

  // El reuso cuenta como intento fallido del mfaToken (máx. 5) y no cambia el último paso guardado.
  const cred = await s.db.get('SELECT attempts FROM credentials WHERE id = $1', [t2.split('.')[0]]);
  assert.equal(cred.attempts, 2);
  assert.equal((await s.db.get('SELECT totp_last_step FROM users WHERE id = $1', [u.user.id])).totp_last_step, pasoNuevo);
});

test('S-07b dos peticiones simultáneas con el mismo código del Authenticator: solo una debe entrar',
  { todo: 'Posible hallazgo: la protección contra reuso lee totp_last_step y lo actualiza en pasos separados; dos peticiones a la vez pueden pasar las dos' }, async () => {
  const email = 's07b@test.com';
  const u = await s.register(email);
  const { totp_last_step: paso } = await s.db.get('SELECT totp_last_step FROM users WHERE id = $1', [u.user.id]);
  const codigo = totpCode(base32Decode(u.totpSecret), paso + 1);
  const tokens = [];
  for (let i = 0; i < 3; i++) tokens.push((await s.api('POST', '/v1/auth/login', { email, password: PW })).body.mfaToken);
  const resultados = await Promise.all(tokens.map((mfaToken) => s.api('POST', '/v1/auth/login/mfa', { mfaToken, code: codigo })));
  const ok = resultados.filter((r) => r.status === 200).length;
  assert.equal(ok, 1, `el mismo código TOTP abrió ${ok} sesiones`);
});