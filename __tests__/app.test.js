const request = require('supertest');
const app = require('../app');

describe('Vaultora API', () => {
  it('GET / responds with a JSON status object', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('POST /echo returns the same JSON sent', async () => {
    const payload = { message: 'Hello Vaultora' };
    const res = await request(app)
      .post('/echo')
      .send(payload)
      .set('Content-Type', 'application/json');

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual(payload);
  });

  it('GET unknown route returns 404', async () => {
    const res = await request(app).get('/does-not-exist');
    expect(res.statusCode).toBe(404);
    expect(res.body).toEqual({ error: 'Not found' });
  });
});
