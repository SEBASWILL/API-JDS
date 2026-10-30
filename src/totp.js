import crypto from 'node:crypto';
import { encrypt, decrypt } from './crypto.js';

// TOTP (RFC 6238): lo que usan Microsoft Authenticator, Google Authenticator, Authy, etc.
const PERIOD = 30;
const DIGITS = 6;
const WINDOW = 1; // acepta el código anterior y el siguiente (±30 s de desfase de reloj)
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  let bits = 0, value = 0;
  const out = [];
  for (const c of str.replace(/=+$/, '').toUpperCase()) {
    const i = B32.indexOf(c);
    if (i < 0) throw new Error('base32 inválido');
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export const currentStep = (now = Date.now()) => Math.floor(now / 1000 / PERIOD);

/** Código de 6 dígitos para un paso de tiempo (HOTP con SHA-1, RFC 4226). */
export function totpCode(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', secret).update(counter).digest();
  const off = h[h.length - 1] & 15;
  const n = (h.readUInt32BE(off) & 0x7fffffff) % 10 ** DIGITS;
  return String(n).padStart(DIGITS, '0');
}

/**
 * Devuelve el paso de tiempo que coincide con el código, o null.
 * Solo acepta pasos posteriores a lastStep: un código ya usado no sirve otra vez.
 */
export function verifyTotp(secret, code, lastStep = null, now = Date.now()) {
  const given = Buffer.from(String(code));
  const step = currentStep(now);
  let match = null;
  for (let s = step - WINDOW; s <= step + WINDOW; s++) {
    const expected = Buffer.from(totpCode(secret, s));
    // Se recorren todos los pasos (sin salir antes) para no filtrar información por tiempo.
    if (expected.length === given.length && crypto.timingSafeEqual(expected, given) && match === null) match = s;
  }
  if (match === null || (lastStep !== null && match <= lastStep)) return null;
  return match;
}

export const newTotpSecret = () => crypto.randomBytes(20);

/** URL que va dentro del QR. El correo solo se usa aquí para que la app muestre la cuenta. */
export function otpauthUrl(secret, account, issuer) {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: base32Encode(secret), issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(PERIOD),
  });
  return `otpauth://totp/${label}?${params}`;
}

// El secreto TOTP se guarda cifrado con la DEK del usuario, como todo lo demás.
const totpAad = (userId) => `user:${userId}:totp`;
export const sealTotp = (dek, userId, secret) => encrypt(dek, secret, totpAad(userId));
export const openTotp = (dek, user) => decrypt(dek, user.totp_enc, totpAad(user.id));
