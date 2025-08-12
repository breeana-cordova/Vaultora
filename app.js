// app.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Joi = require('joi');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const cors = require('cors');

const { createUser, getUserByUsername, insertCredential, getCredentialsByUser, deleteCredential } = require('./db');

// Configure logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : false,
  credentials: true
}));
app.use(express.json());

// Rate limiting for login endpoint
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'test' ? 100 : 5, // Higher limit during testing
  message: { error: 'Too many login attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Config - Make JWT_SECRET mandatory
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  logger.error('JWT_SECRET environment variable is required');
  process.exit(1);
}

// AES encryption key for credentials
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
if (!process.env.ENCRYPTION_KEY) {
  logger.warn('ENCRYPTION_KEY not set, using random key (data will not persist across restarts)');
}

// Validation schemas
const registerSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  password: Joi.string().min(6).required()
});

const loginSchema = Joi.object({
  username: Joi.string().required(),
  password: Joi.string().required()
});

const credentialSchema = Joi.object({
  service: Joi.string().min(1).max(100).required(),
  username: Joi.string().min(1).max(100).required(),
  password: Joi.string().min(1).max(500).required()
});

// --- Helpers ---
function encryptPassword(password) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  
  let encrypted = cipher.update(password, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    tag: '' // CBC mode doesn't use auth tags, but store empty string for database
  };
}

function decryptPassword(encrypted, iv, tag) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(iv, 'hex'));
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    logger.warn('Invalid token attempt', { error: err.message });
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
    // Validate input
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { username, password } = value;
    
    const existing = await getUserByUsername(username);
    if (existing) {
      // idempotent: if user exists, return ok (matches your tests)
      return res.status(200).json({ status: 'ok' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await createUser(username, passwordHash);
    logger.info('User registered successfully', { userId: user.id, username });
    return res.status(200).json({ status: 'ok', id: user.id });
  } catch (err) {
    logger.error('Register error:', err);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// Login - return token
app.post('/login', loginLimiter, async (req, res) => {
  try {
    // Validate input
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { username, password } = value;
    
    const user = await getUserByUsername(username);
    if (!user) {
      logger.warn('Login attempt for non-existent user', { username });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      logger.warn('Failed login attempt', { username });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signToken({ id: user.id, username: user.username });
    logger.info('User logged in successfully', { userId: user.id, username });
    return res.status(200).json({ token });
  } catch (err) {
    logger.error('Login error:', err);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// --- Credential endpoints (basic store/retrieve for future)
// POST /credentials { service, username, password } -> create (requires auth)
// GET /credentials -> list (requires auth)
// DELETE /credentials/:id -> delete (requires auth)
app.post('/credentials', authMiddleware, async (req, res) => {
  try {
    // Validate input
    const { error, value } = credentialSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { service, username: credUser, password } = value;
    
    // Encrypt the password using AES
    const { encrypted, iv, tag } = encryptPassword(password);
    const id = await insertCredential(req.user.id, service, credUser, encrypted, iv, tag);
    
    logger.info('Credential stored successfully', { 
      userId: req.user.id, 
      credentialId: id, 
      service 
    });
    
    res.status(201).json({ id, service, username: credUser });
  } catch (err) {
    logger.error('Credential insert error:', err);
    res.status(500).json({ error: 'Could not store credential' });
  }
});

app.get('/credentials', authMiddleware, async (req, res) => {
  try {
    const rows = await getCredentialsByUser(req.user.id);
    const results = rows.map(r => ({
      id: r.id,
      service: r.service,
      username: r.username
      // Note: password is intentionally excluded for security
    }));
    res.json(results);
  } catch (err) {
    logger.error('Credentials list error:', err);
    res.status(500).json({ error: 'Could not list credentials' });
  }
});

app.delete('/credentials/:id', authMiddleware, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      return res.status(400).json({ error: 'Invalid credential ID' });
    }
    
    const changes = await deleteCredential(id, req.user.id);
    if (changes === 0) {
      return res.status(404).json({ error: 'Credential not found' });
    }
    
    logger.info('Credential deleted successfully', { 
      userId: req.user.id, 
      credentialId: id 
    });
    
    res.status(204).end();
  } catch (err) {
    logger.error('Credential delete error:', err);
    res.status(500).json({ error: 'Could not delete credential' });
  }
});

// 404 and error handlers (last)
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

module.exports = app;
