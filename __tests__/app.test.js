const request = require('supertest');
const app = require('../app');

describe('Vaultora API Routes', () => {
  test('GET / should return running message', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe('Vaultora API is running');
  });

  test('POST /echo should return sent data', async () => {
    const payload = { test: 'data' };
    const res = await request(app).post('/echo').send(payload);
    expect(res.statusCode).toBe(200);
    expect(res.body.youSent).toEqual(payload);
  });

  test('GET /error should return 500', async () => {
    const res = await request(app).get('/error');
    expect(res.statusCode).toBe(500);
  });

  test('POST /register should create a new user', async () => {
    const res = await request(app)
      .post('/register')
      .send({ username: 'testuser', password: 'testpass' });
    expect([201, 409]).toContain(res.statusCode); // 409 if already exists
  });

  test('POST /login should return JWT token', async () => {
    await request(app)
      .post('/register')
      .send({ username: 'loginuser', password: 'pass123' });

    const res = await request(app)
      .post('/login')
      .send({ username: 'loginuser', password: 'pass123' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('token');
  });
});
