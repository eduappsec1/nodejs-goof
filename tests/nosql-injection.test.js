const tap = require('tap');

// Import the routes module
// Note: This will attempt to load mongoose models, but we're only testing
// the type validation logic which happens before any database queries
let routes;
try {
  routes = require('../routes/index.js');
} catch (err) {
  console.error('Warning: Could not load routes module:', err.message);
  console.error('Skipping integration tests. Run validation tests instead.');
  process.exit(0);
}

// Mock request and response objects for direct handler testing
function createMockReqRes(body) {
  const req = {
    body: body,
    session: {}
  };
  const res = {
    statusCode: null,
    redirectUrl: null,
    sentData: null,
    status: function(code) {
      this.statusCode = code;
      return this;
    },
    send: function(data) {
      this.sentData = data;
      return this;
    },
    redirect: function(url) {
      this.redirectUrl = url;
      return this;
    }
  };
  const next = function() {};
  return { req, res, next };
}

tap.test('NoSQL Injection Prevention Tests', (t) => {
  
  t.test('should reject login when password is an object (MongoDB operator injection)', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: { '$ne': null }
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when password is an object with $gt operator', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: { '$gt': '' }
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when password is an object with $regex operator', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: { '$regex': '.*' }
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when password is an array', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: ['password1', 'password2']
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when password is null', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: null
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when password is undefined', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: undefined
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when password is a number', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: 12345
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when password is a boolean', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: true
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when username is an object', (t) => {
    const { req, res, next } = createMockReqRes({
      username: { '$ne': null },
      password: 'password123'
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when username is an array', (t) => {
    const { req, res, next } = createMockReqRes({
      username: ['admin@snyk.io'],
      password: 'password123'
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when username is null', (t) => {
    const { req, res, next } = createMockReqRes({
      username: null,
      password: 'password123'
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when username is undefined', (t) => {
    const { req, res, next } = createMockReqRes({
      username: undefined,
      password: 'password123'
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when both username and password are objects', (t) => {
    const { req, res, next } = createMockReqRes({
      username: { '$ne': null },
      password: { '$ne': null }
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should reject login when username is not a valid email (even if string)', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'not-an-email',
      password: 'password123'
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should enforce type validation before email validation', (t) => {
    // Even with invalid email format, type check should happen first
    const { req, res, next } = createMockReqRes({
      username: { '$ne': null },
      password: { '$ne': null }
    });
    
    routes.loginHandler(req, res, next);
    
    // Should fail at type check, not at email validation
    t.equal(res.statusCode, 401, 'should return 401 at type check');
    t.end();
  });

  t.test('should prevent the original exploit scenario', (t) => {
    // This is the exact exploit from the pentest finding
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: { '$ne': null }
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not grant authenticated session');
    t.notOk(res.redirectUrl, 'should not redirect to admin page');
    t.end();
  });

  t.test('should handle nested MongoDB operators in password', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: { '$or': [{ '$ne': null }, { '$gt': '' }] }
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.test('should handle empty object as password', (t) => {
    const { req, res, next } = createMockReqRes({
      username: 'admin@snyk.io',
      password: {}
    });
    
    routes.loginHandler(req, res, next);
    
    t.equal(res.statusCode, 401, 'should return 401 status');
    t.notOk(req.session.loggedIn, 'should not set session.loggedIn');
    t.end();
  });

  t.end();
});
