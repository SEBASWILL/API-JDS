// PRUEBAS DE VENCIMIENTO DE TOKENS (TK) Y DE VALIDACIÓN DE CONFIGURACIÓN (CF)
//
//   node --test test/tokens-config.test.js
//
// TK: la API guarda en la tabla `credentials` cuándo vence cada token (`expires_at`). Para probar
//     el vencimiento sin esperar una hora (ni 30 días) la prueba edita ese campo directamente en
//     la base de datos temporal: es equivalente a que el tiempo hubiera pasado.
// CF: prueba `loadConfig`, la función que convierte las variables de entorno (.env) en la
//     configuración de la API. No levanta servidor: son pruebas unitarias.
//
// Las marcadas `todo` describen cómo DEBERÍA comportarse la API y hoy no lo hace: se ejecutan y
// muestran el hallazgo, pero no rompen `npm test`. Al corregir el código, quitar la marca `todo`.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, totpFor, mailer } from './helpers.js';
import { loadConfig } from '../src/config.js';

const PW = 'una-clave-larga-123';
const PEPPER = 'a'.repeat(64);

// ===========================================================================
// TK: VENCIMIENTO DE TOKENS
// ===========================================================================
let s;
before(async () => { s = await startServer(); });
after(() => s.stop());

const idDe = (token) => token.split('.')[0];
const fila = (token) => s.db.get('SELECT * FROM credentials WHERE id = $1', [idDe(token)]);
/** Mueve la fecha de vencimiento del token: -1 = venció hace 1 ms; 60000 = vence en un minuto. */
const vencer = (token, deltaMs = -1) =>
  s.db.run('UPDATE credentials SET expires_at = $1 WHERE id = $2', [Date.now() + deltaMs, idDe(token)]);

test('TK-01 cada token se emite con su vigencia: access 1 hora, refresh 30 días, mfa 10 minutos, ingesta sin vencimiento', async () => {
  const reg = await s.register('tk01@test.com');
  const login = await s.api('POST', '/v1/auth/login', { email: 'tk01@test.com', password: PW });
  const ingesta = await s.api('POST', '/v1/ingest-tokens', { label: 'tel' }, reg.accessToken);

  const vigencia = async (token) => { const f = await fila(token); return f.expires_at === null ? null : f.expires_at - f.created_at; };
  assert.equal(await vigencia(reg.accessToken), 60 * 60 * 1000, 'access: 1 hora');
  assert.equal(await vigencia(reg.refreshToken), 30 * 24 * 60 * 60 * 1000, 'refresh: 30 días');
  assert.equal(await vigencia(login.body.mfaToken), 10 * 60 * 1000, 'mfaToken: 10 minutos');
  assert.equal(await vigencia(ingesta.body.token), null, 'el token de ingesta no tiene vencimiento');
  assert.equal(reg.expiresIn, 3600, 'la respuesta informa expiresIn en segundos');
});

test('TK-02 un accessToken vencido da 401 (aunque haya vencido hace 1 ms); uno que vence en el futuro sigue sirviendo', async () => {
  const { accessToken: t } = await s.register('tk02@test.com');

  await vencer(t, 60_000); // vence dentro de un minuto: aún válido
  assert.equal((await s.api('GET', '/v1/transactions', null, t)).status, 200, 'faltando 1 minuto debe servir');

  await vencer(t, -1); // venció hace 1 ms
  for (const ruta of ['/v1/transactions', '/v1/goals', '/v1/reports/daily']) {
    assert.equal((await s.api('GET', ruta, null, t)).status, 401, `${ruta} aceptó un token vencido`);
  }
});

test('TK-03 con el accessToken vencido, el refreshToken entrega una sesión nueva (así se mantiene la sesión abierta)', async () => {
  const reg = await s.register('tk03@test.com');
  await vencer(reg.accessToken);
  assert.equal((await s.api('GET', '/v1/transactions', null, reg.accessToken)).status, 401);

  const r = await s.api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken });
  assert.equal(r.status, 200);
  assert.equal((await s.api('GET', '/v1/transactions', null, r.body.accessToken)).status, 200, 'el access nuevo funciona');
  assert.equal((await s.api('GET', '/v1/transactions', null, reg.accessToken)).status, 401, 'el access vencido sigue vencido');
});

test('TK-04 un refreshToken vencido no sirve (401) y es independiente del accessToken', async () => {
  const reg = await s.register('tk04@test.com');
  await vencer(reg.refreshToken);

  const r = await s.api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken });
  assert.equal(r.status, 401);
  assert.ok(r.body.error, 'el 401 trae el campo error');
  assert.equal((await s.api('GET', '/v1/transactions', null, reg.accessToken)).status, 200, 'el access no depende del vencimiento del refresh');
});

test('TK-05 un mfaToken vencido no sirve ni para iniciar sesión ni para activar el MFA; un login nuevo da otro válido', async () => {
  // a) Login con MFA ya activo
  const reg = await s.register('tk05@test.com');
  const l1 = await s.api('POST', '/v1/auth/login', { email: 'tk05@test.com', password: PW });
  await vencer(l1.body.mfaToken);
  const code = totpFor(reg.totpSecret, 1);
  assert.equal((await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l1.body.mfaToken, code })).status, 401, 'mfaToken vencido');
  const l2 = await s.api('POST', '/v1/auth/login', { email: 'tk05@test.com', password: PW });
  assert.notEqual(l2.body.mfaToken, l1.body.mfaToken);
  assert.equal((await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l2.body.mfaToken, code })).status, 200,
    'con un mfaToken nuevo, el mismo código (que no se gastó) sí sirve');

  // b) Activación del MFA (primer ingreso): el mfaToken del QR también vence
  const email = 'tk05b@test.com';
  await s.api('POST', '/v1/auth/register', { email, password: PW });
  await s.api('POST', '/v1/auth/verify-email', { email, code: mailer.lastCode(email) });
  const a = await s.api('POST', '/v1/auth/login', { email, password: PW });
  assert.equal(a.body.mfaSetupRequired, true);
  await vencer(a.body.mfaToken);
  assert.equal((await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: a.body.mfaToken, code: totpFor(a.body.mfaSetup.secret) })).status, 401, 'QR vencido');
  const b = await s.api('POST', '/v1/auth/login', { email, password: PW });
  assert.equal((await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: b.body.mfaToken, code: totpFor(b.body.mfaSetup.secret) })).status, 200, 'con el QR nuevo sí se activa');
});

test('TK-06 el token de ingesta (Atajo de iOS) no vence: sigue creando gastos y solo se puede revocar', async () => {
  const { accessToken: t } = await s.register('tk06@test.com');
  const tok = (await s.api('POST', '/v1/ingest-tokens', { label: 'tel' }, t)).body.token;
  assert.equal((await fila(tok)).expires_at, null, 'expires_at debe ser NULL');
  const r = await s.api('POST', '/v1/ingest', { merchant: 'Éxito', amount: 25000 }, tok);
  assert.equal(r.status, 201);
});

test('TK-07 al usar un token se registra cuándo (last_used_at); mientras no se use queda vacío', async () => {
  const { accessToken: t } = await s.register('tk07@test.com');
  assert.equal((await fila(t)).last_used_at, null, 'recién emitido: nunca usado');
  const antes = Date.now();
  await s.api('GET', '/v1/transactions', null, t);
  const despues = Date.now();
  const usado = (await fila(t)).last_used_at;
  assert.ok(usado >= antes && usado <= despues, `last_used_at (${usado}) debía estar entre ${antes} y ${despues}`);
});

test('TK-08 las credenciales vencidas se borran de la base',
  { todo: 'Hallazgo: nada borra las credenciales vencidas; cada login y cada refresh agregan filas que se quedan para siempre' }, async () => {
  const reg = await s.register('tk08@test.com');
  let refresh = reg.refreshToken;
  for (let i = 0; i < 3; i++) { // cada refresh crea 2 credenciales nuevas (access + refresh)
    refresh = (await s.api('POST', '/v1/auth/refresh', { refreshToken: refresh })).body.refreshToken;
  }
  const userId = reg.user.id;
  await s.db.run('UPDATE credentials SET expires_at = 1 WHERE user_id = $1 AND expires_at IS NOT NULL', [userId]); // "pasó el tiempo"
  // Actividad posterior: un login nuevo.
  const l = await s.api('POST', '/v1/auth/login', { email: 'tk08@test.com', password: PW });
  await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code: totpFor(reg.totpSecret, 1) });

  const { n: vencidas } = await s.db.get('SELECT COUNT(*) n FROM credentials WHERE user_id = $1 AND expires_at IS NOT NULL AND expires_at < $2',
    [userId, Date.now()]);
  assert.equal(vencidas, 0, `quedan ${vencidas} credenciales vencidas en la base (debería limpiarlas)`);
});

// ===========================================================================
// CF: VALIDACIÓN DE LA CONFIGURACIÓN (loadConfig)
// ===========================================================================
const cfg = (extra = {}) => loadConfig({ PEPPER, ...extra });

test('CF-01 con solo el PEPPER, el resto de la configuración toma sus valores por defecto', () => {
  const c = cfg();
  assert.equal(c.defaultTz, 'America/Bogota');
  assert.equal(c.port, 3000);
  assert.equal(c.databaseUrl, ''); // sin DATABASE_URL la API no arranca (openDb lanza error)
  assert.equal(c.scryptN, 32768);
  assert.equal(c.authRateMax, 20);
  assert.equal(c.accessTtlSec, 3600);
  assert.equal(c.refreshTtlSec, 2_592_000);
  assert.equal(c.mfaTtlSec, 600);
  assert.equal(c.mfaMaxAttempts, 5);
  assert.equal(c.emailCodeTtlSec, 600);
  assert.equal(c.emailCodeMaxAttempts, 5);
  assert.equal(c.emailResendCooldownSec, 60);
  assert.equal(c.mfaIssuer, 'Gastos');
  assert.equal(c.trustProxy, false);
  assert.deepEqual(c.corsOrigins, []);
  assert.equal(c.gmailUser, '');
  assert.equal(c.gmailAppPassword, '');
});

test('CF-02 un PEPPER ausente o mal formado impide arrancar (lanza error)', () => {
  const malos = {
    'sin PEPPER': undefined,
    'vacío': '',
    '63 caracteres': 'a'.repeat(63),
    '65 caracteres': 'a'.repeat(65),
    'no es hexadecimal': 'g'.repeat(64),
    'con espacios': ` ${'a'.repeat(62)} `,
    'entre comillas': `"${'a'.repeat(62)}"`,
    'con guiones': `${'a'.repeat(32)}-${'a'.repeat(31)}`,
  };
  for (const [nombre, pepper] of Object.entries(malos)) {
    assert.throws(() => loadConfig({ PEPPER: pepper }), /PEPPER/, `el PEPPER "${nombre}" se aceptó`);
  }
});

test('CF-03 un PEPPER válido (en mayúsculas o minúsculas) se convierte en 32 bytes', () => {
  const hex = '085d688a4919bfacb164761914ce2f16250179f2d653a6eb68b79bca7fa13d5d';
  const c = loadConfig({ PEPPER: hex });
  assert.equal(c.pepper.length, 32);
  assert.ok(Buffer.isBuffer(c.pepper));
  assert.deepEqual(loadConfig({ PEPPER: hex.toUpperCase() }).pepper, c.pepper, 'mayúsculas y minúsculas dan la misma llave');
});

test('CF-04 DEFAULT_TZ inválida impide arrancar; una zona válida se acepta', () => {
  for (const tz of ['Foo/Bar', 'Bogota', 'UTC+5x', '../etc']) {
    assert.throws(() => cfg({ DEFAULT_TZ: tz }), /DEFAULT_TZ/, `la zona "${tz}" se aceptó`);
  }
  for (const tz of ['America/Bogota', 'Asia/Tokyo', 'UTC']) assert.equal(cfg({ DEFAULT_TZ: tz }).defaultTz, tz);
});

test('CF-05 las variables numéricas válidas llegan como número (y un 0 explícito no se confunde con "sin definir")', () => {
  const c = cfg({ PORT: '8080', AUTH_RATE_MAX: '200', SCRYPT_N: '4096', EMAIL_RESEND_COOLDOWN_SEC: '0' });
  assert.equal(c.port, 8080);
  assert.equal(c.authRateMax, 200);
  assert.equal(c.scryptN, 4096);
  assert.equal(c.emailResendCooldownSec, 0, 'un cooldown de 0 debe respetarse, no volver a 60');
});

test('CF-06 TRUST_PROXY solo se activa con el texto exacto "1" (con "true", "yes" o "0" queda apagado, sin avisar)', () => {
  assert.equal(cfg({ TRUST_PROXY: '1' }).trustProxy, true);
  for (const v of ['0', 'true', 'yes', 'TRUE', '', ' 1']) {
    assert.equal(cfg({ TRUST_PROXY: v }).trustProxy, false, `TRUST_PROXY="${v}"`);
  }
});

test('CF-07 CORS_ORIGINS se separa por comas, recorta espacios y descarta vacíos', () => {
  assert.deepEqual(cfg({ CORS_ORIGINS: 'https://a.com, https://b.com ,,https://c.com' }).corsOrigins,
    ['https://a.com', 'https://b.com', 'https://c.com']);
  assert.deepEqual(cfg({ CORS_ORIGINS: '*' }).corsOrigins, ['*']);
  assert.deepEqual(cfg({ CORS_ORIGINS: '  ' }).corsOrigins, []);
  assert.deepEqual(cfg({ CORS_ORIGINS: '' }).corsOrigins, []);
});

test('CF-08 la contraseña de aplicación de Gmail pierde los espacios; el usuario de Gmail se conserva tal cual', () => {
  const c = cfg({ GMAIL_APP_PASSWORD: 'abcd efgh ijkl mnop', GMAIL_USER: 'Persona@Gmail.com' });
  assert.equal(c.gmailAppPassword, 'abcdefghijklmnop');
  assert.equal(c.gmailAppPassword.length, 16, 'Google espera 16 caracteres');
  assert.equal(c.gmailUser, 'Persona@Gmail.com', 'no se cambia a minúsculas ni se recorta');
  assert.equal(cfg({ GMAIL_APP_PASSWORD: ' \t ' }).gmailAppPassword, '', 'solo espacios queda vacío');
});

test('CF-09 un SCRYPT_N que no es potencia de 2 (o no es número) debe rechazarse al cargar la configuración',
  { todo: 'Hallazgo: loadConfig acepta SCRYPT_N=1000 o "abc" sin error; luego cada registro y login falla con 500 (Invalid scrypt params)' }, () => {
  for (const v of ['1000', '3000', 'abc', '-1024', '1', '1.5']) {
    assert.throws(() => cfg({ SCRYPT_N: v }), /SCRYPT_N/, `SCRYPT_N="${v}" se aceptó`);
  }
});

test('CF-10 PORT y AUTH_RATE_MAX que no son números válidos deben rechazarse al cargar la configuración',
  { todo: 'Hallazgo: loadConfig acepta PORT="abc" y AUTH_RATE_MAX="abc" y los convierte en NaN' }, () => {
  for (const v of ['abc', '-5', '99999999']) {
    assert.throws(() => cfg({ PORT: v }), /PORT/, `PORT="${v}" se aceptó`);
  }
  for (const v of ['abc', '-5', '0']) {
    assert.throws(() => cfg({ AUTH_RATE_MAX: v }), /AUTH_RATE_MAX/, `AUTH_RATE_MAX="${v}" se aceptó`);
  }
});