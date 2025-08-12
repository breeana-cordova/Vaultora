// __tests__/app.test.js
const request = require('supertest');
const app = require('../index');

describe('GET /', () => {
  it('responds with a JSON status object', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });
});
