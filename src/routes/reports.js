import { Router } from 'express';
import { z } from 'zod';
import { ah, requireAuth } from '../middleware.js';
import { listTx, counts } from '../tx.js';
import { tzSchema, dayKey, addDays, weekStart, daysBetween } from '../dates.js';

const r2 = (n) => Math.round(n * 100) / 100;
const roundObj = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, r2(v)]));
const dateKey = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'usa el formato AAAA-MM-DD')
  .refine((s) => !Number.isNaN(Date.parse(s + 'T00:00:00Z')), 'fecha inválida');

const emptyDay = () => ({ total: 0, count: 0, by_category: {}, by_type: { card: 0, cash: 0 } });
function addTo(d, t) {
  d.total += t.amount;
  d.count++;
  const c = t.category ?? 'sin_categoria';
  d.by_category[c] = (d.by_category[c] ?? 0) + t.amount;
  d.by_type[t.type] += t.amount;
}

export function reportsRouter(db, config) {
  const r = Router();
  r.use(requireAuth(db));

  // Transacciones que cuentan como gasto, cada una con su día según la zona horaria del usuario.
  const load = (req, tz) =>
    listTx(db, req.auth.userId, req.auth.dek).filter(counts)
      .map((t) => ({ t, key: dayKey(new Date(t.occurred_at), tz) }));

  r.get('/daily', ah(async (req, res) => {
    const q = z.object({ tz: tzSchema, from: dateKey.optional(), to: dateKey.optional() }).parse(req.query);
    const tz = q.tz || config.defaultTz;
    const to = q.to || dayKey(new Date(), tz);
    const from = q.from || addDays(to, -29);
    const span = daysBetween(from, to) + 1;
    if (span < 1 || span > 366) {
      return res.status(400).json({ error: 'Rango inválido: from debe ser menor o igual a to y máximo 366 días' });
    }

    const byDay = new Map();
    const merchants = new Map();
    for (const { t, key } of load(req, tz)) {
      if (key < from || key > to) continue;
      const d = byDay.get(key) ?? byDay.set(key, emptyDay()).get(key);
      addTo(d, t);
      const mk = t.merchant.trim().toLowerCase();
      const m = merchants.get(mk) ?? merchants.set(mk, { merchant: t.merchant.trim(), total: 0, count: 0 }).get(mk);
      m.total += t.amount;
      m.count++;
    }

    // Todos los días del rango, incluso los que no tuvieron gasto.
    const days = Array.from({ length: span }, (_, i) => {
      const date = addDays(from, i);
      const d = byDay.get(date) ?? emptyDay();
      return { date, total: r2(d.total), count: d.count, by_category: roundObj(d.by_category), by_type: roundObj(d.by_type) };
    });
    const total = r2(days.reduce((a, x) => a + x.total, 0));
    const max = days.reduce((a, x) => (x.total > a.total ? x : a), days[0]);
    res.json({
      tz, from, to, days,
      summary: {
        total,
        avg_per_day: r2(total / span),
        max_day: { date: max.date, total: max.total },
        zero_days: days.filter((x) => !x.total).length,
        top_merchants: [...merchants.values()].sort((a, b) => b.total - a.total).slice(0, 5)
          .map((m) => ({ ...m, total: r2(m.total) })),
      },
    });
  }));

  r.get('/weekly', ah(async (req, res) => {
    const q = z.object({ tz: tzSchema, weeks: z.coerce.number().int().min(1).max(52).default(8) }).parse(req.query);
    const tz = q.tz || config.defaultTz;
    const today = dayKey(new Date(), tz);
    // Se calcula una semana extra al inicio solo para poder comparar la primera.
    const first = addDays(weekStart(today), -7 * q.weeks);
    const buckets = Array.from({ length: q.weeks + 1 }, () => emptyDay());
    for (const { t, key } of load(req, tz)) {
      const i = Math.floor(daysBetween(first, weekStart(key)) / 7);
      if (i >= 0 && i <= q.weeks) addTo(buckets[i], t);
    }

    const weeks = [];
    for (let i = 1; i <= q.weeks; i++) {
      const start = addDays(first, 7 * i);
      const b = buckets[i];
      const prev = buckets[i - 1];
      const elapsed = Math.max(1, Math.min(7, daysBetween(start, today) + 1)); // la semana actual va incompleta
      weeks.push({
        start, end: addDays(start, 6),
        total: r2(b.total), count: b.count, avg_per_day: r2(b.total / elapsed),
        change_pct: prev.total > 0 ? Math.round(((b.total - prev.total) / prev.total) * 100) : null,
        by_category: roundObj(b.by_category),
      });
    }
    const total = r2(weeks.reduce((a, w) => a + w.total, 0));
    res.json({ tz, weeks, summary: { total, avg_per_week: r2(total / q.weeks) } });
  }));

  return r;
}
