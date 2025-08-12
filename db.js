// db.js
const Database = require('better-sqlite3');
const db = new Database('vaultora.db');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    passwordHash TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    passwordEncrypted TEXT NOT NULL,
    iv TEXT NOT NULL,
    tag TEXT NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
  );
`);

module.exports = db;
