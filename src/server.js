import { loadConfig } from './config.js';
import { openDb } from './db.js';
import { createApp } from './app.js';

const config = loadConfig();
const db = openDb(config.dbPath);
createApp(db, config).listen(config.port, '0.0.0.0', () => {
  console.log(`API en http://localhost:${config.port}`);
});