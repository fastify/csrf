'use strict'

const { test, mock } = require('tap')
const Tokens = require('..')

test('Tokens.secret: should reject bad callback', t => {
  t.plan(1)

  t.throws(() => new Tokens().secret(42), new TypeError('argument callback must be a function'))
})

test('Tokens.secret: should create a secret', t => {
  t.plan(3)

  new Tokens().secret(function (err, secret) {
    t.error(err)
    t.type(secret, 'string')
    t.equal(secret.length, 24)
  })
})

test('Tokens.secret: with global Promise', t => {
  t.plan(2)

  new Tokens().secret().then(function (secret) {
    t.type(secret, 'string')
    t.equal(secret.length, 24)
  })
})

test('Tokens.secret: without global Promise', t => {
  t.plan(1)

  const promise = Promise
  global.Promise = undefined
  t.teardown(() => { global.Promise = promise })

  t.throws(() => new Tokens().secret(), new TypeError('argument callback is required'))
})

test('Tokens.secret: without global Promise should reject bad callback', t => {
  t.plan(1)

  const promise = Promise
  global.Promise = undefined
  t.teardown(() => { global.Promise = promise })
  t.throws(() => new Tokens().secret(42), new TypeError('argument callback must be a function'))
})

test('Tokens.secret: should not contain /, +, or =, Promise', t => {
  t.plan(3000)

  for (let i = 0; i < 1000; i++) {
    new Tokens().secret().then(function (secret) {
      t.not(secret.includes('/'))
      t.not(secret.includes('+'))
      t.not(secret.includes('='))
    })
  }
})

test('Tokens.secret: should not contain /, +, or =, callback', t => {
  t.plan(4000)

  for (let i = 0; i < 1000; i++) {
    new Tokens().secret(function (err, secret) {
      t.error(err)
      t.not(secret.includes('/'))
      t.not(secret.includes('+'))
      t.not(secret.includes('='))
    })
  }
})

test('Tokens.secret: should handle error, Promise', t => {
  t.plan(2)

  const Tokens = mock('..', {
    'node:crypto': {
      randomBytes: (_size, cb) => {
        cb(new Error('oh no'))
      },
      createHash: require('node:crypto').createHash
    }
  })

  new Tokens().secret().catch(err => {
    t.ok(err instanceof Error)
    t.ok(err.message = 'oh no')
  })
})

test('Tokens.secret: should handle error, callback', t => {
  t.plan(2)

  const Tokens = mock('..', {
    'node:crypto': {
      randomBytes: (size, cb) => {
        cb(new Error('oh no'))
      },
      createHash: require('node:crypto').createHash
    }
  })

  new Tokens().secret(function (err, _secret) {
    t.ok(err instanceof Error)
    t.ok(err.message = 'oh no')
  })
})
