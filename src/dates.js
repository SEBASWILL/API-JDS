import { z } from 'zod';

/** Zona horaria IANA válida (ej. America/Bogota). */
export function isValidTz(tz) {
  try { new Intl.DateTimeFormat('en-CA', { timeZone: tz }); return true; } catch { return false; }
}
export const tzSchema = z.string().max(64).refine(isValidTz, 'zona horaria inválida').optional();

const fmts = new Map();
/** Fecha calendario (AAAA-MM-DD) de un instante, vista desde una zona horaria. */
export function dayKey(date, tz) {
  let f = fmts.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' });
    fmts.set(tz, f);
  }
  return f.format(date);
}

// Aritmética de calendario sobre claves AAAA-MM-DD (en UTC, sin horarios de verano de por medio).
const utc = (key) => new Date(key + 'T00:00:00Z');
export function addDays(key, n) {
  const d = utc(key);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}
export const daysBetween = (a, b) => Math.round((utc(b) - utc(a)) / 86400000);
/** Lunes de la semana a la que pertenece la fecha. */
export const weekStart = (key) => addDays(key, -((utc(key).getUTCDay() + 6) % 7));
export const daysInMonth = (year, month) => new Date(Date.UTC(year, month, 0)).getUTCDate();
