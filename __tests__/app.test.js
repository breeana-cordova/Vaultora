// __tests__/app.test.js
const fs = require('fs');
const path = require('path');

// set env BEFORE requiring app
process.env.JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey123';
const TEST_DB = path.join(__dirname, 'test_vaultora.db');
process.env.DB_FILE = TEST_DB;

// remove old test DB if left over
if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);

// now require app (it will open DB using process.env.DB_FILE)
const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../app');

// make a token that app will accept
const token = jwt.sign({ username: 'testuser' }, process.env.JWT_SECRET, { expiresIn: '1h' });

beforeAll(async () => {
  // app should create the table on require, but just in case wait a tick
  await new Promise(r => setTimeout(r, 50));
});

afterAll(() => {
  // cleanup DB file
  try { if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB); } catch (e) {}
});

describe('Vaultora API', () => {
  test('POST /credentials should store encrypted password', async () => {
    const res = await request(app)
      .post('/credentials')
      .set('Authorization', `Bearer ${token}`)
      .send({ service: 'gmail', username: 'me', password: 'secret123' });

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('service', 'gmail');
  });

  test('GET /credentials should return decrypted password', async () => {
    const res = await request(app)
      .get('/credentials')
      .set('Authorization', `Bearer ${token}`);

    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body[0]).toHaveProperty('password', 'secret123');
  });
});
