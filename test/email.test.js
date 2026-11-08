import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, mailer } from './helpers.js';

let s;
before(async () => { s = await startServer(); });
after(() => s.stop());

const PW = 'una-clave-larga-123';
const wrong = (code) => String((Number(code) + 1) % 1e6).padStart(6, '0');
const signUp = (email) => s.api('POST', '/v1/auth/register', { email, password: PW });
const verify = (email, code) => s.api('POST', '/v1/auth/verify-email', { email, code });

test('registro envía un código de 6 dígitos y sin verificar no se llega al Authenticator', async () => {
  const r = await signUp('Nuevo@Test.com');
  assert.equal(r.status, 201);
  assert.equal(r.body.emailSent, true);
  const code = mailer.lastCode('nuevo@test.com');
  assert.match(code, /^\d{6}$/);

  const l = await s.api('POST', '/v1/auth/login', { email: 'nuevo@test.com', password: PW });
  assert.equal(l.status, 403);
  assert.equal(l.body.emailVerificationRequired, true);
  assert.equal(l.body.mfaToken, undefined);
  // Contraseña incorrecta sigue siendo 401 (no revela el estado de la cuenta).
  assert.equal((await s.api('POST', '/v1/auth/login', { email: 'nuevo@test.com', password: 'otra-clave-999' })).status, 401);

  const ok = await verify('NUEVO@test.com', `${code.slice(0, 3)} ${code.slice(3)}`);
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.body, { verified: true });
  assert.equal((await verify('nuevo@test.com', code)).status, 200); // idempotente

  const l2 = await s.api('POST', '/v1/auth/login', { email: 'nuevo@test.com', password: PW });
  assert.equal(l2.body.mfaSetupRequired, true);
});

test('5 códigos incorrectos anulan el código; reenviar da uno nuevo y anula el anterior', async () => {
  await signUp('intentos@test.com');
  const code = mailer.lastCode('intentos@test.com');
  for (let i = 0; i < 5; i++) {
    const bad = await verify('intentos@test.com', wrong(code));
    assert.equal(bad.status, 401);
    assert.equal(bad.body.attemptsLeft, 4 - i);
  }
  const blocked = await verify('intentos@test.com', code);
  assert.equal(blocked.status, 400);
  assert.match(blocked.body.error, /Demasiados intentos/);

  assert.equal((await s.api('POST', '/v1/auth/resend-code', { email: 'intentos@test.com' })).status, 200);
  const fresh = mailer.lastCode('intentos@test.com');
  if (fresh !== code) assert.equal((await verify('intentos@test.com', code)).status, 401); // el viejo ya no sirve
  assert.equal((await verify('intentos@test.com', fresh)).status, 200);
});

test('el código vence a los 10 minutos', async () => {
  const r = await signUp('vence@test.com');
  s.db.prepare('UPDATE users SET email_code_expires_at = ? WHERE id = ?').run(Date.now() - 1, r.body.user.id);
  const res = await verify('vence@test.com', mailer.lastCode('vence@test.com'));
  assert.equal(res.status, 400);
  assert.match(res.body.error, /venció/);
});

test('el código se guarda como HMAC, nunca en claro', async () => {
  const r = await signUp('hash@test.com');
  const row = s.db.prepare('SELECT * FROM users WHERE id = ?').get(r.body.user.id);
  const code = mailer.lastCode('hash@test.com');
  assert.ok(Buffer.isBuffer(row.email_code_hash) && row.email_code_hash.length === 32);
  assert.ok(!row.email_code_hash.toString('hex').includes(code));
  assert.ok(row.email_code_expires_at - Date.now() <= 10 * 60 * 1000);
});

test('resend-code: respuesta genérica para correos inexistentes o ya verificados', async () => {
  const before = mailer.sent.length;
  const ghost = await s.api('POST', '/v1/auth/resend-code', { email: 'nadie@test.com' });
  assert.equal(ghost.status, 200);
  const verified = await s.api('POST', '/v1/auth/resend-code', { email: 'nuevo@test.com' });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.message, ghost.body.message);
  assert.equal(mailer.sent.length, before);
  assert.equal((await verify('nadie@test.com', '123456')).status, 400);
});

test('si Gmail falla, el registro igual responde 201 con emailSent: false', async () => {
  mailer.fail = true;
  try {
    const r = await signUp('smtp-caido@test.com');
    assert.equal(r.status, 201);
    assert.equal(r.body.emailSent, false);
    assert.ok(r.body.recoveryKey);
    assert.equal((await s.api('POST', '/v1/auth/resend-code', { email: 'smtp-caido@test.com' })).status, 502);
  } finally {
    mailer.fail = false;
  }
  assert.equal((await s.api('POST', '/v1/auth/resend-code', { email: 'smtp-caido@test.com' })).status, 200);
  assert.equal((await verify('smtp-caido@test.com', mailer.lastCode('smtp-caido@test.com'))).status, 200);
});

test('resend-code respeta la espera entre envíos', async () => {
  const slow = await startServer({ EMAIL_RESEND_COOLDOWN_SEC: '60' });
  try {
    await slow.api('POST', '/v1/auth/register', { email: 'espera@test.com', password: PW });
    const r = await slow.api('POST', '/v1/auth/resend-code', { email: 'espera@test.com' });
    assert.equal(r.status, 429);
    assert.ok(r.body.retryAfterSec > 0 && r.body.retryAfterSec <= 60);
  } finally {
    slow.stop();
  }
});

test('el límite de intentos responde 429 en JSON', async () => {
  const tiny = await startServer({ AUTH_RATE_MAX: '2' });
  try {
    for (let i = 0; i < 2; i++) await tiny.api('POST', '/v1/auth/login', { email: 'x@test.com', password: 'x' });
    const r = await tiny.api('POST', '/v1/auth/login', { email: 'x@test.com', password: 'x' });
    assert.equal(r.status, 429);
    assert.equal(typeof r.body.error, 'string');
    assert.ok(r.body.retryAfterSec > 0);
  } finally {
    tiny.stop();
  }
});
