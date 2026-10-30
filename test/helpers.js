import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { base32Decode, totpCode, currentStep } from '../src/totp.js';

/** Lo que mostraría el Authenticator para ese secreto (offset en pasos de 30 s). */
export const totpFor = (secretB32, offset = 0) => totpCode(base32Decode(secretB32), currentStep() + offset);

/** Registro completo: crea la cuenta y confirma el QR. Devuelve registro + sesión + secreto TOTP. */
export async function registerWithMfa(api, email, password = 'una-clave-larga-123') {
  const r = await api('POST', '/v1/auth/register', { email, password });
  assert.equal(r.status, 201);
  const { secret } = r.body.mfaSetup;
  const c = await api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: r.body.mfaToken, code: totpFor(secret) });
  assert.equal(c.status, 200);
  return { ...r.body, ...c.body, totpSecret: secret };
}

export async function startServer(extraEnv = {}) {
  const env = { PEPPER: 'a'.repeat(64), SCRYPT_N: '1024', AUTH_RATE_MAX: '1000', ...extraEnv };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gastos-'));
  const dbFile = path.join(dir, 'test.db');
  const db = openDb(dbFile);
  const app = createApp(db, loadConfig(env));
  const server = await new Promise((ok) => { const s = app.listen(0, () => ok(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;

  const api = async (method, url, body, token) => {
    const res = await fetch(base + url, {
      method,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };
  const register = (email, password) => registerWithMfa(api, email, password);
  const stop = () => { server.close(); db.close(); fs.rmSync(dir, { recursive: true, force: true }); };
  return { api, register, db, dbFile, stop };
}
