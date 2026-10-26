import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
const VERSION = 1;

/** AES-256-GCM. Formato: [version(1) | iv(12) | tag(16) | ciphertext]. */
export function encrypt(key, plaintext, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from([VERSION]), iv, cipher.getAuthTag(), ct]);
}

/** Lanza error si la llave es incorrecta, el AAD no coincide o el dato fue alterado. */
export function decrypt(key, blob, aad) {
  const b = Buffer.from(blob);
  if (b.length < 29 || b[0] !== VERSION) throw new Error('formato inválido');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(1, 13));
  decipher.setAuthTag(b.subarray(13, 29));
  if (aad) decipher.setAAD(Buffer.from(aad));
  return Buffer.concat([decipher.update(b.subarray(29)), decipher.final()]);
}

/** Deriva una llave de 32 bytes desde un secreto de alta entropía (tokens, recovery key). */
export function hkdf(secret, salt, info) {
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(secret), Buffer.from(salt), Buffer.from(info), 32));
}

/**
 * Contraseña -> llave. Primero HMAC con el pepper (que vive en el servidor, no en la BD)
 * y luego scrypt. Sin el pepper, un dump de la BD no permite ni probar contraseñas.
 */
export async function deriveFromPassword(password, salt, pepper, N) {
  const pre = crypto.createHmac('sha256', pepper).update(password.normalize('NFKC')).digest();
  return scrypt(pre, salt, 32, { N, r: 8, p: 1, maxmem: 256 * N * 8 });
}

/** El correo no se guarda: solo un HMAC para poder buscar al usuario. */
export function emailLookup(email, pepper) {
  return crypto.createHmac('sha256', pepper).update(email.trim().toLowerCase()).digest('hex');
}

export const randomKey = () => crypto.randomBytes(32);
export const randomSalt = () => crypto.randomBytes(16);
export const newId = () => crypto.randomUUID();
