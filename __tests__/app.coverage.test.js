const request = require('supertest');
const jwt = require('jsonwebtoken');

// Import everything we need from app.js
const { app, encrypt, decrypt } = require('../app');

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey123';
const validToken = jwt.sign({ username: 'testuser' }, JWT_SECRET);

describe('Vaultora API - Full Coverage', () => {
  // --- encrypt() tests ---
  test('encrypt throws if input is not a string', () => {
    expect(() => encrypt(123)).toThrow('Password must be a string');
  });

  test('encrypt returns a valid iv:encrypted string', () => {
    const result = encrypt('mypassword');
    expect(result).toMatch(/^[0-9a-f]+:[0-9a-f]+$/i);
  });

  // --- decrypt() tests ---
  test('decrypt returns original string', () => {
    const encrypted = encrypt('secret');
    expect(decrypt(encrypted)).toBe('secret');
  });

  test('decrypt returns null on malformed input', () => {
    expect(decrypt('notvalid')).toBeNull();
  });

  // --- authenticateToken() via routes ---
  test('GET /credentials returns 401 if no token provided', async () => {
    const res = await request(app).get('/credentials');
    expect(res.status).toBe(401);
  });

  test('GET /credentials returns 403 if token invalid', async () => {
    const res = await request(app)
      .get('/credentials')
      .set('Authorization', 'Bearer invalidtoken');
    expect(res.status).toBe(403);
  });

  // --- /login route ---
  test('POST /login returns 400 if username missing', async () => {
    const res = await request(app).post('/login').send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  test('POST /login returns token if username provided', async () => {
    const res = await request(app).post('/login').send({ username: 'alice' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('token');
  });

  // --- /credentials POST route ---
  test('POST /credentials returns 400 if fields missing', async () => {
    const res = await request(app)
      .post('/credentials')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ service: 'svc' });
    expect(res.status).toBe(400);
  });

  test('POST /credentials returns 500 if encryption fails', async () => {
    jest.spyOn(require('../app'), 'encrypt').mockImplementation(() => {
      throw new Error('Forced encryption fail');
    });
    const res = await request(app)
      .post('/credentials')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ service: 'svc', username: 'u', password: 'p' });
    expect(res.status).toBe(500);
    require('../app').encrypt.mockRestore();
  });

  test('POST /credentials inserts successfully', async () => {
    const res = await request(app)
      .post('/credentials')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ service: 'svc', username: 'u', password: 'p' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('id');
  });

  // --- /credentials GET route ---
  test('GET /credentials fetches and decrypts stored credentials', async () => {
    const postRes = await request(app)
      .post('/credentials')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ service: 'svc2', username: 'u2', password: 'p2' });

    expect(postRes.status).toBe(200);

    const getRes = await request(app)
      .get('/credentials')
      .set('Authorization', `Bearer ${validToken}`);

    expect(getRes.status).toBe(200);
    expect(getRes.body.length).toBeGreaterThan(0);
    expect(getRes.body[0]).toHaveProperty('password');
  });
});
