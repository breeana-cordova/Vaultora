// __tests__/app.test.js
const request = require('supertest');
const app = require('../app');

describe('Vaultora API basic tests', () => {
  beforeAll(async () => {
    // ensure the user exists for the login test
    await request(app)
      .post('/register')
      .send({ username: 'loginuser', password: 'pass123' });
  });

  test('should return hello world on GET /', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toBe(200);
    expect(res.text).toBe('Hello World!');
  });

  test('should register a new user on POST /register', async () => {
    const res = await request(app)
      .post('/register')
      .send({ username: 'testuser', password: 'password' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('status', 'ok');
  });

  test('should login an existing user on POST /login', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: 'loginuser', password: 'pass123' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('token');
  });

  test('should return 404 for unknown route', async () => {
    const res = await request(app).get('/does-not-exist');
    expect(res.statusCode).toBe(404);
    expect(res.body).toHaveProperty('error');
  });
});
