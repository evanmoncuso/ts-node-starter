import { createTokenAuthMiddleware } from '../lib/authenticate';
import { sign } from 'jsonwebtoken';

const TESTING_SECRET = 'testing-secret'

// generate a fake req object
function createRequestMock(handlers) {
  return {
    headers: {},
    ...handlers,
  }
}

// generate a fake res object
function createResponseMock(handlers) {
  return {
    status() { return this },
    send() { return this },
    ...handlers,
  }
}

// generate a fake nextFunction call
function createNextMock(cb) {
  if (cb) return cb;

  return () => null
}

function generateWorkingToken(payload) {
  const token = sign(payload, TESTING_SECRET, {
    expiresIn: 1000,
    issuer: 'testing',
  });

  return token
}

describe('authenticateToken creates a middleware function', () => {
  test('Function generates a new function', () => {
    const m = createTokenAuthMiddleware();
    expect(typeof m).toBe('function');
  });
});

describe('Works on the happy path', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV, }
    process.env.ACCESS_TOKEN_SECRET = TESTING_SECRET;
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
  });

  test('Sometimes things are right as rain', () => {return new Promise((done) => {
    const t = generateWorkingToken({
      id: '1234',
      username: 'test-user',
      permissions: [ 'TESTING', ],
    });
    
    const req = createRequestMock({
      headers: {
        'authorization': `Bearer ${t}`,
      },
    });
    const res = createResponseMock({
      locals: {
        x: 1,
      }
    });

    const fn = jest.fn();
    const next = createNextMock(fn);

    const middleware = createTokenAuthMiddleware();
    middleware(req, res, next);

    expect(fn).toHaveBeenCalled();
    expect(res.locals.id).toBe('1234');
    expect(res.locals.username).toBe('test-user');
    expect(res.locals.permissions).toEqual([ 'TESTING', ]);

    expect(res.locals.x).toBe(1);

    done();
  })});
});

describe('Does not allow unauthorized requests through', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV, }
    process.env.ACCESS_TOKEN_SECRET = TESTING_SECRET;
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
  });

  test('Returns a 401 when no "Authorization" header is present', () => {return new Promise((done) => {
    const req = createRequestMock();
    const res = createResponseMock({
      send(message) { 
        expect(message.error).toBe('No Authorization Header present');
        return this;
      },
      status(statusCode) {
        expect(statusCode).toBe(401);
        return this;
      },
    });

    const fn = jest.fn();
    const next = createNextMock(fn);

    const middleware = createTokenAuthMiddleware();
    middleware(req, res, next);

    expect(fn).not.toHaveBeenCalled();

    done();
  })});

  test('Returns a 401 when "Authorization" header is not a Bearer', () => {return new Promise((done) => {
    const req = createRequestMock({
      headers: {
        'authorization': 'ham',
      },
    });
    const res = createResponseMock({
      send(message) {
        expect(message.error).toBe('Authorization is not a "Bearer" token');
        return this;
      },
      status(statusCode) {
        expect(statusCode).toBe(401);
        return this;
      },
    });

    const fn = jest.fn();
    const next = createNextMock(fn);

    const middleware = createTokenAuthMiddleware();
    middleware(req, res, next);

    expect(fn).not.toHaveBeenCalled();

    done();
  })});

  test('Returns a 401 when "Authorization" header is not a Bearer', () => {return new Promise((done) => {

    const req = createRequestMock({
      headers: {
        'authorization': `ham`,
      },
    });
    const res = createResponseMock({
      send(message) {
        expect(message.error).toBe('Authorization is not a "Bearer" token');
        return this;
      },
      status(statusCode) {
        expect(statusCode).toBe(401);
        return this;
      },
    });

    const fn = jest.fn();
    const next = createNextMock(fn);

    const middleware = createTokenAuthMiddleware();
    middleware(req, res, next);

    expect(fn).not.toHaveBeenCalled();

    done();
  })});

});



describe('Correctly restricts roles', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV, }
    process.env.ACCESS_TOKEN_SECRET = TESTING_SECRET;
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
  });

  test('Allows requests when "roles" is present', () => {return new Promise((done) => {
    const t = generateWorkingToken({
      id: '1234',
      username: 'test-user',
      permissions: ['TESTING',],
    });

    const req = createRequestMock({
      headers: {
        'authorization': `Bearer ${t}`,
      },
    });
    const res = createResponseMock({
      locals: {
        x: 1,
      },
    });

    const fn = jest.fn();
    const next = createNextMock(fn);

    const middleware = createTokenAuthMiddleware({ allowRoles: ['TESTING',], });
    middleware(req, res, next);

    expect(fn).toHaveBeenCalled();
    expect(res.locals.id).toBe('1234');
    expect(res.locals.username).toBe('test-user');
    expect(res.locals.permissions).toEqual(['TESTING',]);

    expect(res.locals.x).toBe(1);

    done();
  })});

  test('Does not filter when "roles" is empty array', () => {return new Promise((done) => {
    const t = generateWorkingToken({
      id: '1234',
      username: 'test-user',
      permissions: ['TESTING',],
    });

    const req = createRequestMock({
      headers: {
        'authorization': `Bearer ${t}`,
      },
    });
    const res = createResponseMock({
      locals: {
        x: 1,
      },
    });

    const fn = jest.fn();
    const next = createNextMock(fn);

    const middleware = createTokenAuthMiddleware({ allowRoles: [], });
    middleware(req, res, next);

    expect(fn).toHaveBeenCalled();
    expect(res.locals.id).toBe('1234');
    expect(res.locals.username).toBe('test-user');
    expect(res.locals.permissions).toEqual(['TESTING',]);

    expect(res.locals.x).toBe(1);

    done();
  })});



  test('Denies requests when "roles" is not present', () => {return new Promise((done) => {
    const t = generateWorkingToken({
      id: '1234',
      username: 'test-user',
      permissions: [ 'TESTING', ],
    });

    const req = createRequestMock({
      headers: {
        'authorization': `Bearer ${t}`,
      },
    });
    const res = createResponseMock({
      send(message) {
        expect(message.error).toBe('Incorrect Permissions');
        return this;
      },
      status(statusCode) {
        expect(statusCode).toBe(401);
        return this;
      },
    });

    const fn = jest.fn();
    const next = createNextMock(fn);

    // only allow admins
    const middleware = createTokenAuthMiddleware({ allowRoles: [ 'ADMIN', ], });
    middleware(req, res, next);

    expect(fn).not.toHaveBeenCalled();

    done();
  })});

  test('Allows requests when role is not in "denyRoles"', () => {return new Promise((done) => {
    const t = generateWorkingToken({
      id: '1234',
      username: 'test-user',
      permissions: [ 'TESTING', ],
    });

    const req = createRequestMock({
      headers: {
        'authorization': `Bearer ${t}`,
      },
    });
    const res = createResponseMock({
      locals: {
        x: 1,
      },
    });

    const fn = jest.fn();
    const next = createNextMock(fn);

    const middleware = createTokenAuthMiddleware({ denyRoles: ['USER',], });
    middleware(req, res, next);

    expect(fn).toHaveBeenCalled();
    expect(res.locals.id).toBe('1234');
    expect(res.locals.username).toBe('test-user');
    expect(res.locals.permissions).toEqual(['TESTING',]);

    expect(res.locals.x).toBe(1);

    done();
  })});

  test('Does not filter when "denyRoles" is empty array', () => {return new Promise((done) => {
    const t = generateWorkingToken({
      id: '1234',
      username: 'test-user',
      permissions: ['TESTING',],
    });

    const req = createRequestMock({
      headers: {
        'authorization': `Bearer ${t}`,
      },
    });
    const res = createResponseMock({
      locals: {
        x: 1,
      },
    });

    const fn = jest.fn();
    const next = createNextMock(fn);

    const middleware = createTokenAuthMiddleware({ denyRoles: [], });
    middleware(req, res, next);

    expect(fn).toHaveBeenCalled();
    expect(res.locals.id).toBe('1234');
    expect(res.locals.username).toBe('test-user');
    expect(res.locals.permissions).toEqual(['TESTING',]);

    expect(res.locals.x).toBe(1);

    done();
  })});

  test('Denies requests when role is not present', () => {return new Promise((done) => {
    const t = generateWorkingToken({
      id: '1234',
      username: 'test-user',
      permissions: [ 'TESTING', 'USER', ],
    });

    const req = createRequestMock({
      headers: {
        'authorization': `Bearer ${t}`,
      },
    });
    const res = createResponseMock({
      send(message) {
        expect(message.error).toBe('Incorrect Permissions');
        return this;
      },
      status(statusCode) {
        expect(statusCode).toBe(401);
        return this;
      },
    });

    const fn = jest.fn();
    const next = createNextMock(fn);

    // only allow admins
    const middleware = createTokenAuthMiddleware({ denyRoles: ['USER',], });
    middleware(req, res, next);

    expect(fn).not.toHaveBeenCalled();

    done();
  })});
});