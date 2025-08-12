// app.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { createUser, getUserByUsername, insertCredential, getCredentialsByUser, deleteCredential } = require('./db');

const app = express();
app.use(express.json());

// Config
const JWT_SECRET = process.env.JWT_SECRET || 'please-change-this-secret';

// --- Helpers ---
function signToken(user) {
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

// Root: tests expect plain text Hello World! so return that
app.get('/', (req, res) => {
  res.status(200).send('Hello World!');
});

// Echo route (kept for previous tests)
app.post('/echo', (req, res) => {
  res.status(200).json({ youSent: req.body });
});

// Error route (for testing server error handler)
app.get('/error', (req, res, next) => {
  next(new Error('Simulated server failure'));
});

// Register - create new user
// Tests expect status 200 + { status: 'ok' } on success
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const existing = getUserByUsername(username);
    if (existing) {
      // idempotent: if user exists, return ok (matches your tests)
      return res.status(200).json({ status: 'ok' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = createUser(username, passwordHash);
    return res.status(200).json({ status: 'ok', id: user.id });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// Login - return token
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const user = getUserByUsername(username);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ id: user.id, username: user.username });
    return res.status(200).json({ token });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// --- Credential endpoints (basic store/retrieve for future)
// POST /credentials { service, username, password } -> create (requires auth)
// GET /credentials -> list (requires auth)
// DELETE /credentials/:id -> delete (requires auth)
app.post('/credentials', authMiddleware, (req, res) => {
  try {
    const { service, username: credUser, password } = req.body || {};
    if (!service || !credUser || !password) return res.status(400).json({ error: 'service, username and password required' });

    // For now we store plaintext in passwordEncrypted to keep MVP working.
    // We'll replace this with AES encryption in the next step (and tests).
    const encrypted = Buffer.from(String(password)).toString('base64'); // placeholder
    const id = insertCredential(req.user.id, service, credUser, encrypted, null, null);
    res.status(201).json({ id, service, username: credUser });
  } catch (err) {
    console.error('Credential insert error:', err);
    res.status(500).json({ error: 'Could not store credential' });
  }
});

app.get('/credentials', authMiddleware, (req, res) => {
  try {
    const rows = getCredentialsByUser(req.user.id);
    const results = rows.map(r => ({
      id: r.id,
      service: r.service,
      username: r.username,
      password: Buffer.from(r.passwordEncrypted, 'base64').toString('utf8') // decode placeholder
    }));
    res.json(results);
  } catch (err) {
    console.error('Credentials list error:', err);
    res.status(500).json({ error: 'Could not list credentials' });
  }
});

app.delete('/credentials/:id', authMiddleware, (req, res) => {
  try {
    const id = Number(req.params.id);
    const changes = deleteCredential(id, req.user.id);
    if (changes === 0) return res.status(404).json({ error: 'Credential not found' });
    res.status(204).end();
  } catch (err) {
    console.error('Credential delete error:', err);
    res.status(500).json({ error: 'Could not delete credential' });
  }
});

// 404 and error handlers (last)
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

app.use((err, req, res, next) => {
  console.error(err && err.stack ? err.stack : err);
  res.status(500).json({ error: 'Internal Server Error' });
});

module.exports = app;
