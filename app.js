// app.js
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
app.use(express.json());

// Config: require at least JWT_SECRET; ENCRYPTION_KEY must be 32 bytes (base64 or raw)
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-to-a-strong-secret';
let ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || null;

// If no encryption key provided, generate a temporary one (not for production)
if (!ENCRYPTION_KEY) {
  console.warn('WARNING: ENCRYPTION_KEY not set. Generating a temporary key for dev only.');
  ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex'); // 64 hex chars => 32 bytes
}
// ensure buffer
const ENCRYPTION_KEY_BUF = Buffer.from(ENCRYPTION_KEY, 'hex').length === 32
  ? Buffer.from(ENCRYPTION_KEY, 'hex')
  : Buffer.from(ENCRYPTION_KEY);

// --- Helper: AES-256-GCM encrypt/decrypt ---
function encryptText(plain) {
  const iv = crypto.randomBytes(12); // 96-bit IV recommended for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY_BUF, iv);
  const encrypted = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    cipherText: encrypted.toString('base64'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

function decryptText(cipherTextB64, ivHex, tagHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const encrypted = Buffer.from(cipherTextB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY_BUF, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

// --- Auth helpers ---
function signToken(user) {
  // minimal payload
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '8h' });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Routes ---

// Health
app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

// Register: { username, password }
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const passwordHash = await bcrypt.hash(password, 12);
    const stmt = db.prepare('INSERT INTO users (username, passwordHash) VALUES (?, ?)');
    const info = stmt.run(username, passwordHash);
    const user = { id: info.lastInsertRowid, username };
    const token = signToken(user);
    res.status(201).json({ id: user.id, username: user.username, token });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login: { username, password }
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const row = db.prepare('SELECT id, username, passwordHash FROM users WHERE username = ?').get(username);
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, row.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ id: row.id, username: row.username });
    res.json({ id: row.id, username: row.username, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Create credential: POST /credentials { service, username, password }
// Auth required
app.post('/credentials', authMiddleware, (req, res) => {
  try {
    const { service, username: credUsername, password } = req.body || {};
    if (!service || !credUsername || !password) {
      return res.status(400).json({ error: 'service, username and password required' });
    }

    const { cipherText, iv, tag } = encryptText(password);
    const stmt = db.prepare('INSERT INTO credentials (userId, service, username, passwordEncrypted, iv, tag) VALUES (?, ?, ?, ?, ?, ?)');
    const info = stmt.run(req.user.id, service, credUsername, cipherText, iv, tag);
    res.status(201).json({ id: info.lastInsertRowid, service, username: credUsername });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not store credential' });
  }
});

// List credentials for current user: GET /credentials
app.get('/credentials', authMiddleware, (req, res) => {
  try {
    const rows = db.prepare('SELECT id, service, username, passwordEncrypted, iv, tag FROM credentials WHERE userId = ?').all(req.user.id);
    const results = rows.map(r => {
      const decrypted = decryptText(r.passwordEncrypted, r.iv, r.tag);
      return { id: r.id, service: r.service, username: r.username, password: decrypted };
    });
    res.json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not list credentials' });
  }
});

// Delete credential: DELETE /credentials/:id
app.delete('/credentials/:id', authMiddleware, (req, res) => {
  try {
    const id = Number(req.params.id);
    const stmt = db.prepare('DELETE FROM credentials WHERE id = ? AND userId = ?');
    const info = stmt.run(id, req.user.id);
    if (info.changes === 0) return res.status(404).json({ error: 'Credential not found' });
    res.status(204).end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not delete credential' });
  }
});

// 404 and error handlers (keep last)
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});

module.exports = app;
