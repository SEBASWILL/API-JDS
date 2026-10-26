import crypto from 'node:crypto';
import { encrypt, decrypt, hkdf, deriveFromPassword, randomKey, randomSalt } from './crypto.js';

const PREFIX = { access: 'at_', refresh: 'rt_', ingest: 'it_' };
const pwAad = (userId) => `user:${userId}:pw`;
const recAad = (userId) => `user:${userId}:rec`;

export const formatRecoveryKey = (buf) => buf.toString('hex').match(/.{8}/g).join('-');
const recoveryKeyBytes = (str) => Buffer.from(String(str).replace(/-/g, ''), 'hex');
const recKek = (rk, userId) => hkdf(rk, userId, 'gastos:recovery');

/** Crea la DEK del usuario y la envuelve con contraseña y con llave de recuperación. */
export async function createUserKeys(userId, password, config) {
  const dek = randomKey();
  const salt = randomSalt();
  const kek = await deriveFromPassword(password, salt, config.pepper, config.scryptN);
  const recoveryKey = crypto.randomBytes(32);
  return {
    dek,
    salt,
    n: config.scryptN,
    wrappedPw: encrypt(kek, dek, pwAad(userId)),
    wrappedRec: encrypt(recKek(recoveryKey, userId), dek, recAad(userId)),
    recoveryKey: formatRecoveryKey(recoveryKey),
  };
}

/** Devuelve la DEK o null si la contraseña es incorrecta (el tag GCM lo verifica). */
export async function unlockWithPassword(user, password, config) {
  try {
    const kek = await deriveFromPassword(password, user.kdf_salt, config.pepper, user.kdf_n);
    return decrypt(kek, user.wrapped_dek_pw, pwAad(user.id));
  } catch {
    return null;
  }
}

export function unlockWithRecovery(user, recoveryKey) {
  try {
    const rk = recoveryKeyBytes(recoveryKey);
    if (rk.length !== 32) return null;
    return decrypt(recKek(rk, user.id), user.wrapped_dek_rec, recAad(user.id));
  } catch {
    return null;
  }
}

/** Re-envuelve la misma DEK con una contraseña nueva (los datos no se re-cifran). */
export async function rewrapPassword(userId, dek, newPassword, config) {
  const salt = randomSalt();
  const kek = await deriveFromPassword(newPassword, salt, config.pepper, config.scryptN);
  return { salt, n: config.scryptN, wrappedPw: encrypt(kek, dek, pwAad(userId)) };
}

export function newRecoveryKey(userId, dek) {
  const rk = crypto.randomBytes(32);
  return { wrappedRec: encrypt(recKek(rk, userId), dek, recAad(userId)), recoveryKey: formatRecoveryKey(rk) };
}

// ---------- Credenciales (access / refresh / ingest) ----------

const credKey = (secret, id, kind) => hkdf(secret, id, `gastos:cred:${kind}`);
const credAad = (id, userId) => `cred:${id}:${userId}`;

export function issueCredential(db, { userId, dek, kind, ttlSec = null, label = null }) {
  const id = PREFIX[kind] + crypto.randomBytes(9).toString('base64url');
  const secret = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  db.prepare(
    `INSERT INTO credentials (id,user_id,kind,label_enc,wrapped_dek,created_at,expires_at)
     VALUES (?,?,?,?,?,?,?)`,
  ).run(
    id, userId, kind,
    label ? encrypt(dek, Buffer.from(label), `label:${id}`) : null,
    encrypt(credKey(secret, id, kind), dek, credAad(id, userId)),
    now,
    ttlSec ? now + ttlSec * 1000 : null,
  );
  return `${id}.${secret}`;
}

export function issueSession(db, userId, dek, config) {
  return {
    accessToken: issueCredential(db, { userId, dek, kind: 'access', ttlSec: config.accessTtlSec }),
    refreshToken: issueCredential(db, { userId, dek, kind: 'refresh', ttlSec: config.refreshTtlSec }),
    expiresIn: config.accessTtlSec,
  };
}

/** Valida un token y devuelve { userId, dek, credId, kind } o null. */
export function authenticateToken(db, token, kinds) {
  const parts = String(token || '').split('.');
  if (parts.length !== 2) return null;
  const [id, secret] = parts;
  const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(id);
  if (!row || row.revoked_at || !kinds.includes(row.kind)) return null;
  if (row.expires_at && row.expires_at < Date.now()) return null;
  let dek;
  try {
    dek = decrypt(credKey(secret, id, row.kind), row.wrapped_dek, credAad(id, row.user_id));
  } catch {
    return null;
  }
  db.prepare('UPDATE credentials SET last_used_at = ? WHERE id = ?').run(Date.now(), id);
  return { userId: row.user_id, dek, credId: id, kind: row.kind };
}

export const revokeCredential = (db, id) =>
  db.prepare('UPDATE credentials SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(Date.now(), id);

export const revokeAllSessions = (db, userId) =>
  db.prepare(`UPDATE credentials SET revoked_at = ? WHERE user_id = ? AND kind IN ('access','refresh') AND revoked_at IS NULL`)
    .run(Date.now(), userId);

export const decryptLabel = (row, dek) =>
  row.label_enc ? decrypt(dek, row.label_enc, `label:${row.id}`).toString() : null;
