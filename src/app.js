import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { authRouter } from './routes/auth.js';
import { tokensRouter } from './routes/tokens.js';
import { ingestRouter } from './routes/ingest.js';
import { transactionsRouter } from './routes/transactions.js';
import { reportsRouter } from './routes/reports.js';
import { goalsRouter } from './routes/goals.js';
import { errorHandler } from './middleware.js';

export function createApp(db, config) {
  const app = express();
  if (config.trustProxy) app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(helmet());
  //app.use(cors({ origin: config.corsOrigins, allowedHeaders: ['Content-Type', 'Authorization'] }));
  app.use(cors({
    origin: config.corsOrigins.includes('*') ? true : config.corsOrigins,
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));
  app.use(express.json({ limit: '20kb' }));

  app.get('/health', (_req, res) => res.json({ ok: true }));
  app.use('/v1/auth', authRouter(db, config));
  app.use('/v1/ingest-tokens', tokensRouter(db));
  app.use('/v1/ingest', ingestRouter(db));
  app.use('/v1/transactions', transactionsRouter(db));
  app.use('/v1/reports', reportsRouter(db, config));
  app.use('/v1/goals', goalsRouter(db, config));
  app.use((_req, res) => res.status(404).json({ error: 'Ruta no encontrada' }));
  app.use(errorHandler);
  return app;
}
