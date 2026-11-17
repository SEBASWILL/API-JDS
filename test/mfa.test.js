import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { totpCode, verifyTotp, base32Encode, base32Decode, currentStep } from '../src/totp.js';
import { startServer, totpFor, mailer } from './helpers.js';

let s;
before(async () => { s = await startServer(); });
after(() => s.stop());

const PW = 'una-clave-larga-123';
const wrong = (code) => String((Number(code) + 1) % 1e6).padStart(6, '0');

test('TOTP: vectores del RFC 6238 y base32 de ida y vuelta', () => {
  const secret = Buffer.from('12345678901234567890');
  assert.equal(totpCode(secret, 1), '287082'); // T = 59 s
  assert.equal(totpCode(secret, 37037036), '081804'); // T = 1111111109 s
  assert.deepEqual(base32Decode(base32Encode(secret)), secret);
  assert.equal(base32Encode(secret), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');

  const now = Date.now();
  const step = currentStep(now);
  assert.equal(verifyTotp(secret, totpCode(secret, step), null, now), step);
  assert.equal(verifyTotp(secret, totpCode(secret, step - 1), null, now), step - 1); // desfase de reloj
  assert.equal(verifyTotp(secret, totpCode(secret, step - 2), null, now), null); // demasiado viejo
  assert.equal(verifyTotp(secret, totpCode(secret, step), step, now), null); // ya usado
});

test('registro: tras verificar el correo, el login entrega QR y no da sesión hasta confirmar', async () => {
  const r = await s.api('POST', '/v1/auth/register', { email: 'qr@test.com', password: PW });
  assert.equal(r.status, 201);
  assert.equal(r.body.emailVerificationRequired, true);
  assert.equal(r.body.mfaToken, undefined);
  assert.equal(r.body.mfaSetup, undefined);
  assert.ok(r.body.recoveryKey);
  assert.equal((await s.api('POST', '/v1/auth/verify-email', { email: 'qr@test.com', code: mailer.lastCode('qr@test.com') })).status, 200);

  const first = await s.api('POST', '/v1/auth/login', { email: 'qr@test.com', password: PW });
  assert.equal(first.body.mfaSetupRequired, true);
  assert.equal(first.body.accessToken, undefined);
  assert.match(first.body.mfaSetup.qrCode, /^data:image\/png;base64,/);
  assert.match(first.body.mfaSetup.otpauthUrl, /^otpauth:\/\/totp\/Gastos%3Aqr%40test\.com\?secret=[A-Z2-7]+&issuer=Gastos/);
  const { secret } = first.body.mfaSetup;

  // El mfaToken no sirve como token de acceso.
  assert.equal((await s.api('GET', '/v1/transactions', null, first.body.mfaToken)).status, 401);

  // Sin confirmar, el login vuelve a pedir configurar (QR nuevo).
  const l = await s.api('POST', '/v1/auth/login', { email: 'qr@test.com', password: PW });
  assert.equal(l.body.mfaSetupRequired, true);
  assert.notEqual(l.body.mfaSetup.secret, secret);
  // El login normal con MFA aún no aplica.
  assert.equal((await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code: totpFor(l.body.mfaSetup.secret) })).status, 409);

  const bad = await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: l.body.mfaToken, code: wrong(totpFor(l.body.mfaSetup.secret)) });
  assert.equal(bad.status, 401);
  const ok = await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: l.body.mfaToken, code: totpFor(l.body.mfaSetup.secret) });
  assert.equal(ok.status, 200);
  assert.ok(ok.body.accessToken && ok.body.refreshToken);
  assert.equal((await s.api('GET', '/v1/transactions', null, ok.body.accessToken)).status, 200);

  // Token de un solo uso; y ya activo, no se puede volver a "confirmar".
  assert.equal((await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: l.body.mfaToken, code: totpFor(l.body.mfaSetup.secret, 1) })).status, 401);
  const l2 = await s.api('POST', '/v1/auth/login', { email: 'qr@test.com', password: PW });
  assert.equal(l2.body.mfaRequired, true);
  assert.equal((await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: l2.body.mfaToken, code: totpFor(l.body.mfaSetup.secret, 1) })).status, 409);
});

test('login: pide el código, rechaza código reusado y acepta el código con espacios', async () => {
  const { totpSecret } = await s.register('login-mfa@test.com');
  const l = await s.api('POST', '/v1/auth/login', { email: 'login-mfa@test.com', password: PW });
  assert.deepEqual(Object.keys(l.body).sort(), ['mfaRequired', 'mfaToken', 'user']);

  // El código usado al confirmar el QR no sirve otra vez.
  assert.equal((await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code: totpFor(totpSecret) })).status, 401);
  const next = totpFor(totpSecret, 1);
  const ok = await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code: `${next.slice(0, 3)} ${next.slice(3)}` });
  assert.equal(ok.status, 200);
  assert.ok(ok.body.accessToken);

  const fmt = await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code: 'abc' });
  assert.equal(fmt.status, 400);
});

test('login: 5 códigos incorrectos anulan el mfaToken', async () => {
  const { totpSecret } = await s.register('fuerza-bruta@test.com');
  const l = await s.api('POST', '/v1/auth/login', { email: 'fuerza-bruta@test.com', password: PW });
  const good = totpFor(totpSecret, 1);
  for (let i = 0; i < 5; i++) {
    assert.equal((await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code: wrong(good) })).status, 401);
  }
  assert.equal((await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code: good })).status, 401);
});

test('el Atajo de iOS sigue funcionando sin MFA', async () => {
  const { accessToken } = await s.register('atajo-mfa@test.com');
  const tok = await s.api('POST', '/v1/ingest-tokens', { label: 'iPhone' }, accessToken);
  assert.equal((await s.api('POST', '/v1/ingest', { merchant: 'Rappi', amount: 1000 }, tok.body.token)).status, 201);
});

test('recuperar con la llave reinicia el MFA: el Authenticator viejo deja de servir', async () => {
  const reg = await s.register('perdi-celular@test.com');
  const rec = await s.api('POST', '/v1/auth/recover',
    { email: 'perdi-celular@test.com', recoveryKey: reg.recoveryKey, newPassword: 'clave-nueva-12345' });
  assert.equal(rec.body.mfaSetupRequired, true);
  assert.equal((await s.api('GET', '/v1/transactions', null, reg.accessToken)).status, 401); // sesiones revocadas
  const old = await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: rec.body.mfaToken, code: totpFor(reg.totpSecret, 1) });
  assert.equal(old.status, 401);
  const ok = await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: rec.body.mfaToken, code: totpFor(rec.body.mfaSetup.secret) });
  assert.equal(ok.status, 200);
});

