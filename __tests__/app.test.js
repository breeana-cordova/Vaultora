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

  test('GET /nonexistent should return 404', async () => {
    const res = await request(app).get('/nonexistent');
    expect(res.statusCode).toBe(404);
    expect(res.body.error).toBe('Not Found');
  });

  test('GET /error should return 500', async () => {
    const res = await request(app).get('/error');
    expect(res.statusCode).toBe(500);
    expect(res.body.error).toBe('Internal Server Error');
  });
});
