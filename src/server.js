import { loadConfig } from './config.js';
import { openDb } from './db.js';
import { createApp } from './app.js';

// En local lee el .env; en el servidor (Elastic Beanstalk, etc.) las variables ya vienen del entorno.
try { process.loadEnvFile(); } catch { /* sin .env: se usan las variables del sistema */ }

const config = loadConfig();
const db = openDb(config.dbPath);
createApp(db, config).listen(config.port, '0.0.0.0', () => {
  console.log(`API en http://localhost:${config.port}`);
});
