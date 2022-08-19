'use strict'

const test = require('tap').test
const Tokens = require('..')

test('Tokens.create: should require secret', t => {
  t.plan(1)

  t.throws(() => new Tokens().create(), new TypeError('argument secret is required'))
})

test('Tokens.create: should reject non-string secret', t => {
  t.plan(1)

  t.throws(() => new Tokens().create(42), new TypeError('argument secret is required'))
})

test('Tokens.create: should reject empty string secret', t => {
  t.plan(1)

  t.throws(() => new Tokens().create(''), new TypeError('argument secret is required'))
})

test('Tokens.create: should create a token', t => {
  t.plan(1)

  const secret = new Tokens().secretSync()
  t.type(new Tokens().create(secret), 'string')
})

test('Tokens.create: should always be the same length', t => {
  t.plan(1001)

  const secret = new Tokens().secretSync()
  const tokenLength = new Tokens().create(secret).length

  t.equal(tokenLength, 36)

  for (let i = 0; i < 1000; i++) {
    t.equal(new Tokens().create(secret).length, tokenLength)
  }
})

test('Tokens.create: should not contain /, +, or =', t => {
  t.plan(3000)

  const secret = new Tokens().secretSync()

  for (let i = 0; i < 1000; i++) {
    t.not(new Tokens().create(secret).includes('/'))
    t.not(new Tokens().create(secret).includes('+'))
    t.not(new Tokens().create(secret).includes('='))
  }
})

test('Tokens.create: should not collide', t => {
  t.plan(1000)

  const secret = new Tokens().secretSync()
  const tokenSet = new Set()

  for (let i = 0; i < 1000; i++) {
    const token = new Tokens().create(secret)
    t.not(tokenSet.has(token))
    tokenSet.add(token)
  }
})

test('.create(): should reject undefined string userInfo (create)', t => {
  t.plan(1)

  const secret = new Tokens().secretSync()

  t.throws(() => new Tokens({ userInfo: true }).create(secret), new Error('argument userInfo is required to be a string'))
})
