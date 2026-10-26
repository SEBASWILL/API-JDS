import { Router } from 'express';
import { ah, requireAuth } from '../middleware.js';
import { ingestSchema, parseLooseDate, sealTx } from '../tx.js';
import { newId } from '../crypto.js';

/** Endpoint que llama el Atajo de iOS al pagar con Apple Pay. */
export function ingestRouter(db) {
  const r = Router();

  r.post('/', requireAuth(db, ['ingest']), ah(async (req, res) => {
    const b = ingestSchema.parse(req.body);
    const id = newId();
    const now = new Date().toISOString();
    const payload = {
      type: 'card', merchant: b.merchant, amount: b.amount, currency: b.currency,
      card: b.card ?? null, occurred_at: parseLooseDate(b.date).toISOString(),
      description: b.description ?? null, status: b.status, category: null,
      source: 'ios-shortcut', created_at: now, updated_at: now,
    };
    db.prepare('INSERT INTO transactions (id,user_id,data) VALUES (?,?,?)')
      .run(id, req.auth.userId, sealTx(req.auth.dek, req.auth.userId, id, payload));
    res.status(201).json({ id });
  }));

  return r;
}
