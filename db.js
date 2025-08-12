const Database = require('better-sqlite3');
const db = new Database(process.env.DB_FILE || 'vaultora.db');

// Create users table if it doesn't exist
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`).run();

module.exports = db;
