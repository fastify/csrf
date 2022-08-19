'use strict'

const test = require('tap').test
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

  global.Promise = undefined

  t.throws(() => new Tokens().secret(), new TypeError('argument callback is required'))

  global.Promise = Promise
})

test('Tokens.secret: without global Promise should reject bad callback', t => {
  t.plan(1)

  global.Promise = undefined

  t.throws(() => new Tokens().secret(42), new TypeError('argument callback must be a function'))

  global.Promise = Promise
})
