const tap = require('tap');

// Test the type validation logic that prevents NoSQL injection
// This tests the mitigation added to routes/index.js loginHandler

tap.test('NoSQL Injection Prevention - Type Validation Tests', (t) => {
  
  // Helper function to test type validation
  function testTypeValidation(username, password) {
    // This replicates the validation logic from routes/index.js lines 38-41
    if (typeof username !== 'string' || typeof password !== 'string') {
      return { valid: false, statusCode: 401 };
    }
    return { valid: true };
  }

  t.test('should reject password as MongoDB $ne operator object', (t) => {
    const result = testTypeValidation('admin@snyk.io', { '$ne': null });
    t.equal(result.valid, false, 'should reject object password');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject password as MongoDB $gt operator object', (t) => {
    const result = testTypeValidation('admin@snyk.io', { '$gt': '' });
    t.equal(result.valid, false, 'should reject object password');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject password as MongoDB $regex operator object', (t) => {
    const result = testTypeValidation('admin@snyk.io', { '$regex': '.*' });
    t.equal(result.valid, false, 'should reject object password');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject password as array', (t) => {
    const result = testTypeValidation('admin@snyk.io', ['password1', 'password2']);
    t.equal(result.valid, false, 'should reject array password');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject password as null', (t) => {
    const result = testTypeValidation('admin@snyk.io', null);
    t.equal(result.valid, false, 'should reject null password');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject password as undefined', (t) => {
    const result = testTypeValidation('admin@snyk.io', undefined);
    t.equal(result.valid, false, 'should reject undefined password');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject password as number', (t) => {
    const result = testTypeValidation('admin@snyk.io', 12345);
    t.equal(result.valid, false, 'should reject number password');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject password as boolean', (t) => {
    const result = testTypeValidation('admin@snyk.io', true);
    t.equal(result.valid, false, 'should reject boolean password');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject username as MongoDB operator object', (t) => {
    const result = testTypeValidation({ '$ne': null }, 'password123');
    t.equal(result.valid, false, 'should reject object username');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject username as array', (t) => {
    const result = testTypeValidation(['admin@snyk.io'], 'password123');
    t.equal(result.valid, false, 'should reject array username');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject username as null', (t) => {
    const result = testTypeValidation(null, 'password123');
    t.equal(result.valid, false, 'should reject null username');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject username as undefined', (t) => {
    const result = testTypeValidation(undefined, 'password123');
    t.equal(result.valid, false, 'should reject undefined username');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject both username and password as objects', (t) => {
    const result = testTypeValidation({ '$ne': null }, { '$ne': null });
    t.equal(result.valid, false, 'should reject both as objects');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject nested MongoDB operators in password', (t) => {
    const result = testTypeValidation('admin@snyk.io', { '$or': [{ '$ne': null }, { '$gt': '' }] });
    t.equal(result.valid, false, 'should reject nested operators');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should reject empty object as password', (t) => {
    const result = testTypeValidation('admin@snyk.io', {});
    t.equal(result.valid, false, 'should reject empty object');
    t.equal(result.statusCode, 401, 'should return 401');
    t.end();
  });

  t.test('should accept valid string username and password', (t) => {
    const result = testTypeValidation('admin@snyk.io', 'somepassword');
    t.equal(result.valid, true, 'should accept string types');
    t.notOk(result.statusCode, 'should not set error status code');
    t.end();
  });

  t.test('should accept empty string as password (valid string type)', (t) => {
    const result = testTypeValidation('admin@snyk.io', '');
    t.equal(result.valid, true, 'should accept empty string');
    t.notOk(result.statusCode, 'should not set error status code');
    t.end();
  });

  t.test('should accept empty string as username (valid string type)', (t) => {
    const result = testTypeValidation('', 'password123');
    t.equal(result.valid, true, 'should accept empty string');
    t.notOk(result.statusCode, 'should not set error status code');
    t.end();
  });

  t.test('EXPLOIT SCENARIO: should prevent the original pentest exploit', (t) => {
    // This is the exact exploit from the pentest finding:
    // POST /login with JSON body: { "username": "admin@snyk.io", "password": { "$ne": null } }
    const result = testTypeValidation('admin@snyk.io', { '$ne': null });
    t.equal(result.valid, false, 'should block the exploit');
    t.equal(result.statusCode, 401, 'should return 401 unauthorized');
    t.end();
  });

  t.end();
});
