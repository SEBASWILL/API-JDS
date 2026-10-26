import { isValidTz } from './dates.js';

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
    dbPath: env.DB_PATH || './data/gastos.db',
    pepper: Buffer.from(pepperHex, 'hex'),
    scryptN: Number(env.SCRYPT_N || 32768),
    authRateMax: Number(env.AUTH_RATE_MAX || 20),
    accessTtlSec: 60 * 60, // 1 hora
    refreshTtlSec: 30 * 24 * 60 * 60, // 30 días
    trustProxy: env.TRUST_PROXY === '1',
    corsOrigins: (env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean),
  };
}
