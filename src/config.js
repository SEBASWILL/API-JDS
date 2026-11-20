import { isValidTz } from './dates.js';
import { emailLookup } from './crypto.js';

export function loadConfig(env = process.env) {
  const pepperHex = env.PEPPER;
  if (!pepperHex || !/^[0-9a-f]{64}$/i.test(pepperHex)) {
    throw new Error('PEPPER debe ser 64 caracteres hex (genera uno con: openssl rand -hex 32)');
  }
  const defaultTz = env.DEFAULT_TZ || 'America/Bogota';
  if (!isValidTz(defaultTz)) throw new Error('DEFAULT_TZ no es una zona horaria válida: ' + defaultTz);
  return {
    defaultTz,
    port: Number(env.PORT || 3000),
    databaseUrl: env.DATABASE_URL || '', // Supabase: Connect -> Session pooler
    pepper: Buffer.from(pepperHex, 'hex'),
    scryptN: Number(env.SCRYPT_N || 32768),
    authRateMax: Number(env.AUTH_RATE_MAX || 20),
    accessTtlSec: 60 * 60, // 1 hora
    refreshTtlSec: 30 * 24 * 60 * 60, // 30 días
    mfaTtlSec: 10 * 60, // tiempo para escanear el QR o escribir el código
    mfaMaxAttempts: 5, // códigos incorrectos antes de anular el mfaToken
    mfaIssuer: env.MFA_ISSUER || 'Gastos', // nombre que muestra la app Authenticator
    emailCodeTtlSec: 10 * 60, // vigencia del código enviado al correo
    emailCodeMaxAttempts: 5, // códigos incorrectos antes de anularlo
    emailResendCooldownSec: Number(env.EMAIL_RESEND_COOLDOWN_SEC ?? 60), // espera mínima entre reenvíos
    gmailUser: env.GMAIL_USER || '',
    gmailAppPassword: (env.GMAIL_APP_PASSWORD || '').replace(/\s/g, ''), // Google la muestra con espacios
    mailFrom: env.MAIL_FROM || '',
    trustProxy: env.TRUST_PROXY === '1',
    corsOrigins: (env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean),
    // La cuenta registrada con este correo es el administrador (se compara por HMAC, como el login).
    adminLookup: env.ADMIN_EMAIL ? emailLookup(env.ADMIN_EMAIL, Buffer.from(pepperHex, 'hex')) : null,
  };
}
