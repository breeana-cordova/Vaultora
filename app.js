require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey123';
const DB_FILE = process.env.DB_FILE || 'vaultora.db';
const ENCRYPTION_KEY = crypto.createHash('sha256').update(JWT_SECRET).digest();
const IV_LENGTH = 16;

const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL
  )`);
});

function encrypt(text) {
  if (typeof text !== 'string') throw new Error('Password must be a string to encrypt');
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
  try {
    const [ivHex, encrypted] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error('Decryption error:', err);
    return null;
  }
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.post('/login', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });
  const token = jwt.sign({ username }, JWT_SECRET);
  res.json({ token });
});

app.post('/credentials', authenticateToken, (req, res) => {
  const { service, username, password } = req.body;
  if (!service || !username || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  let encryptedPassword;
  try {
    encryptedPassword = encrypt(password);
  } catch (err) {
    console.error('Encryption error:', err);
    return res.status(500).json({ error: 'Encryption failed' });
  }

  db.run(
    'INSERT INTO credentials (user_id, service, username, password) VALUES (?, ?, ?, ?)',
    [req.user.username, service, username, encryptedPassword],
    function (err) {
      if (err) {
        console.error('DB Insert Error:', err);
        return res.status(500).json({ error: 'Database insert error' });
      }
      res.status(200).json({ id: this.lastID, service, username });
    }
  );
});

app.get('/credentials', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM credentials WHERE user_id = ?',
    [req.user.username],
    (err, rows) => {
      if (err) {
        console.error('DB Fetch Error:', err);
        return res.status(500).json({ error: 'Database fetch error' });
      }
      const decryptedRows = rows.map(row => ({
        id: row.id,
        service: row.service,
        username: row.username,
        password: decrypt(row.password)
      }));
      res.status(200).json(decryptedRows);
    }
  );
});

// Start server only if file is run directly
if (require.main === module) {
  app.listen(PORT, () => console.log(`Vaultora API running on port ${PORT}`));
}

// Export everything we need for testing
module.exports = { app, encrypt, decrypt, authenticateToken };
