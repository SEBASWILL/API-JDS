import { z } from 'zod';
import { encrypt, decrypt } from './crypto.js';
import { parseAmount } from './amount.js';

export const STATUSES = ['approved', 'declined', 'pending', 'refunded'];

export const amountSchema = z.union([z.number(), z.string()]).transform((v, ctx) => {
  const a = parseAmount(v);
  if (a === null) {
    ctx.addIssue({ code: 'custom', message: 'monto inválido' });
    return z.NEVER;
  }
  return a;
});

const currency = z.string().length(3).transform((s) => s.toUpperCase());
const shape = {
  type: z.enum(['card', 'cash']).default('card'),
  merchant: z.string().trim().min(1).max(200),
  amount: amountSchema,
  currency: currency.default('COP'),
  card: z.string().trim().max(60).nullish(),
  occurred_at: z.string().datetime({ offset: true }).optional(),
  description: z.string().max(1000).nullish(),
  status: z.enum(STATUSES).default('approved'),
  category: z.string().trim().max(60).nullish(),
  source: z.enum(['manual', 'web', 'android', 'ios-app']).default('manual'),
};

export const createSchema = z.object(shape).strict();
export const updateSchema = z
  .object(shape).omit({ source: true }).partial().strict()
  .refine((o) => Object.keys(o).length > 0, { message: 'Envía al menos un campo' });

// Lo que manda el Atajo de iOS: más permisivo, ignora campos desconocidos.
export const ingestSchema = z.object({
  merchant: z.string().trim().min(1).max(200),
  amount: amountSchema,
  currency: currency.default('COP'),
  card: z.string().trim().max(60).nullish(),
  date: z.string().max(100).optional(),
  status: z.enum(STATUSES).default('approved'),
  description: z.string().max(1000).nullish(),
});

export function parseLooseDate(s) {
  const t = s ? Date.parse(s) : NaN;
  return Number.isNaN(t) ? new Date() : new Date(t);
}

// AAD ata el cifrado a (usuario, transacción): no se pueden mover filas entre usuarios ni entre ids.
const aad = (userId, id) => `tx:${userId}:${id}`;

export const sealTx = (dek, userId, id, payload) =>
  encrypt(dek, Buffer.from(JSON.stringify(payload)), aad(userId, id));

export function openTx(dek, row) {
  try {
    return { id: row.id, ...JSON.parse(decrypt(dek, row.data, aad(row.user_id, row.id)).toString()) };
  } catch {
    const e = new Error('tx integrity');
    e.code = 'TX_INTEGRITY';
    throw e;
  }
}

/** Todas las transacciones de un usuario, descifradas. */
export const listTx = (db, userId, dek) =>
  db.prepare('SELECT * FROM transactions WHERE user_id = ?').all(userId).map((row) => openTx(dek, row));

/** Solo aprobadas y pendientes cuentan como gasto (no declinadas ni reembolsadas). */
export const counts = (t) => t.status === 'approved' || t.status === 'pending';
