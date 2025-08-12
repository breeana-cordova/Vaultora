// __tests__/credentials.test.js
const request = require('supertest');
const app = require('../app');

describe('Credentials API security tests', () => {
  let authToken;
  let uniqueUser;

  beforeAll(async () => {
    // Register and login to get a token with unique user
    uniqueUser = `creduser${Date.now()}`;
    await request(app)
      .post('/register')
      .send({ username: uniqueUser, password: 'password123' });
    
    const loginRes = await request(app)
      .post('/login')
      .send({ username: uniqueUser, password: 'password123' });
    
    authToken = loginRes.body.token;
  });

  test('should require authentication for credentials endpoints', async () => {
    const res = await request(app)
      .get('/credentials');
    expect(res.statusCode).toBe(401);
    expect(res.body).toHaveProperty('error', 'Unauthorized');
  });

  test('should validate input for POST /credentials', async () => {
    const res = await request(app)
      .post('/credentials')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ service: '', username: 'test', password: 'pass' });
    
    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  test('should store and retrieve credentials securely', async () => {
    // Store a credential
    const storeRes = await request(app)
      .post('/credentials')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ 
        service: 'testservice', 
        username: 'testuser', 
        password: 'testpassword' 
      });
    
    expect(storeRes.statusCode).toBe(201);
    expect(storeRes.body).toHaveProperty('id');
    expect(storeRes.body).toHaveProperty('service', 'testservice');
    expect(storeRes.body).toHaveProperty('username', 'testuser');

    // Retrieve credentials
    const getRes = await request(app)
      .get('/credentials')
      .set('Authorization', `Bearer ${authToken}`);
    
    expect(getRes.statusCode).toBe(200);
    expect(Array.isArray(getRes.body)).toBe(true);
    expect(getRes.body.length).toBeGreaterThan(0);
    
    const credential = getRes.body.find(c => c.service === 'testservice');
    expect(credential).toBeDefined();
    expect(credential).toHaveProperty('service', 'testservice');
    expect(credential).toHaveProperty('username', 'testuser');
    // Password should NOT be returned for security
    expect(credential).not.toHaveProperty('password');
  });

  test('should validate credential deletion with ownership', async () => {
    // Try to delete non-existent credential
    const res = await request(app)
      .delete('/credentials/99999')
      .set('Authorization', `Bearer ${authToken}`);
    
    expect(res.statusCode).toBe(404);
    expect(res.body).toHaveProperty('error', 'Credential not found');
  });

  test('should validate credential ID format', async () => {
    const res = await request(app)
      .delete('/credentials/invalid')
      .set('Authorization', `Bearer ${authToken}`);
    
    expect(res.statusCode).toBe(400);
    expect(res.body).toHaveProperty('error', 'Invalid credential ID');
  });
});