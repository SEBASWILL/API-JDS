import crypto from 'node:crypto';

/** Código de 6 dígitos para verificar el correo. */
export const newEmailCode = () => String(crypto.randomInt(0, 1e6)).padStart(6, '0');

/** Solo se guarda un HMAC del código (atado al usuario), nunca el código en claro. */
export const hashEmailCode = (code, userId, pepper) =>
  crypto.createHmac('sha256', pepper).update(`email-code:${userId}:${code}`).digest();

export const sameHash = (a, b) => Buffer.isBuffer(b) && a.length === b.length && crypto.timingSafeEqual(a, b);
