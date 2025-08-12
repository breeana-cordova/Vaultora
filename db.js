// db.js
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = process.env.DB_FILE || path.join(__dirname, 'vaultora.db');

// ensure parent directory exists (if user used a nested path)
const parent = path.dirname(DB_PATH);
if (!fs.existsSync(parent)) {
  fs.mkdirSync(parent, { recursive: true });
}

const db = new Database(DB_PATH);

// Create tables if they don't exist
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
  iv TEXT,
  tag TEXT,
  FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
);
`);

module.exports = {
  db,
  // helper: create user, returns { id, username } or throws
  createUser: async (username, passwordHash) => {
    const stmt = db.prepare('INSERT INTO users (username, passwordHash) VALUES (?, ?)');
    const info = stmt.run(username, passwordHash);
    return { id: info.lastInsertRowid, username };
  },
  // helper: get user by username
  getUserByUsername: async (username) => {
    return db.prepare('SELECT id, username, passwordHash FROM users WHERE username = ?').get(username);
  },
  // helper for credentials (we'll expand later)
  insertCredential: async (userId, service, username, passwordEncrypted, iv = null, tag = null) => {
    const stmt = db.prepare('INSERT INTO credentials (userId, service, username, passwordEncrypted, iv, tag) VALUES (?, ?, ?, ?, ?, ?)');
    const info = stmt.run(userId, service, username, passwordEncrypted, iv, tag);
    return info.lastInsertRowid;
  },
  getCredentialsByUser: async (userId) => {
    return db.prepare('SELECT id, service, username, passwordEncrypted, iv, tag FROM credentials WHERE userId = ?').all(userId);
  },
  deleteCredential: async (id, userId) => {
    const stmt = db.prepare('DELETE FROM credentials WHERE id = ? AND userId = ?');
    return stmt.run(id, userId).changes;
  }
};
