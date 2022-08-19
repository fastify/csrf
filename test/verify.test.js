'use strict'

const test = require('tap').test
const Tokens = require('..')

test('Tokens.verify: should return `true` with valid tokens', t => {
  t.plan(1)

  const secret = new Tokens().secretSync()
  const token = new Tokens().create(secret)

  t.equal(new Tokens().verify(secret, token), true)
})

test('Tokens.verify: should return `false` with invalid secret', t => {
  t.plan(5)

  const secret = new Tokens().secretSync()
  const token = new Tokens().create(secret)

  t.equal(new Tokens().verify(new Tokens().secretSync(), token), false)
  t.equal(new Tokens().verify('invalid', token), false)
  t.equal(new Tokens().verify(), false)
  t.equal(new Tokens().verify([]), false)
  t.equal(new Tokens().verify('invalid'), false)
})

test('Tokens.verify: should return `false` with invalid tokens', t => {
  t.plan(4)

  const secret = new Tokens().secretSync()
  const token = new Tokens().create(secret)

  t.equal(new Tokens().verify('invalid', token), false)
  t.equal(new Tokens().verify(secret, undefined), false)
  t.equal(new Tokens().verify(secret, []), false)
  t.equal(new Tokens().verify(secret, 'hi'), false)
})
