'use strict'

const test = require('tap').test
const Tokens = require('..')

test('Tokens.constructor: instantiating Tokens with a non string hmacKey should throw', t => {
  t.plan(1)
  t.throws(() => new Tokens({ hmacKey: 123 }), new TypeError('option hmacKey must be a supported hmac key'))
})

test('Tokens.secret: should create a secret', t => {
  t.plan(3)

  new Tokens({ hmacKey: 'foo' }).secret(function (err, secret) {
    t.error(err)
    t.type(secret, 'string')
    t.equal(secret.length, 24)
  })
})

test('Tokens.verify: should return `true` with valid tokens', t => {
  t.plan(1)

  const secret = new Tokens({ hmacKey: 'foo' }).secretSync()
  const token = new Tokens({ hmacKey: 'foo' }).create(secret)

  t.equal(new Tokens({ hmacKey: 'foo' }).verify(secret, token), true)
})

test('Tokens.verify: should return `false` with invalid secret', t => {
  t.plan(5)

  const secret = new Tokens({ hmacKey: 'foo' }).secretSync()
  const token = new Tokens({ hmacKey: 'foo' }).create(secret)

  t.equal(new Tokens({ hmacKey: 'foo' }).verify(new Tokens().secretSync(), token), false)
  t.equal(new Tokens({ hmacKey: 'foo' }).verify('invalid', token), false)
  t.equal(new Tokens({ hmacKey: 'foo' }).verify(), false)
  t.equal(new Tokens({ hmacKey: 'foo' }).verify([]), false)
  t.equal(new Tokens({ hmacKey: 'foo' }).verify('invalid'), false)
})

test('Tokens.verify: should return `false` with invalid tokens', t => {
  t.plan(4)

  const secret = new Tokens({ hmacKey: 'foo' }).secretSync()
  const token = new Tokens({ hmacKey: 'foo' }).create(secret)

  t.equal(new Tokens({ hmacKey: 'foo' }).verify('invalid', token), false)
  t.equal(new Tokens({ hmacKey: 'foo' }).verify(secret, undefined), false)
  t.equal(new Tokens({ hmacKey: 'foo' }).verify(secret, []), false)
  t.equal(new Tokens({ hmacKey: 'foo' }).verify(secret, 'hi'), false)
})

test('Tokens.verify: should return `false` with different hmac key', t => {
  t.plan(2)

  const secret = new Tokens({ hmacKey: 'foo' }).secretSync()
  const token = new Tokens({ hmacKey: 'foo' }).create(secret)

  t.equal(new Tokens({ hmacKey: 'foo' }).verify(secret, token), true)
  t.equal(new Tokens({ hmacKey: 'bar' }).verify(secret, token), false)
})
