'use strict'

const test = require('tap').test
const Tokens = require('..')

test('Tokens.secretSync: should generate secret with specified byte length', t => {
  t.plan(2)

  // 3 bytes = 4 base-64 characters
  // 4 bytes = 6 base-64 characters
  t.equal(new Tokens({ secretLength: 3 }).secretSync().length, 4)
  t.equal(new Tokens({ secretLength: 4 }).secretSync().length, 6)
})

test('Tokens.secretSync: should create a secret', t => {
  t.plan(2)

  const secret = new Tokens().secretSync()
  t.type(secret, 'string')
  t.equal(secret.length, 24)
})

test('Tokens.secretSync: should not contain /, +, or = when using base64', t => {
  t.plan(3000)

  for (let i = 0; i < 1000; i++) {
    t.not(new Tokens().secretSync().includes('/'))
    t.not(new Tokens().secretSync().includes('+'))
    t.not(new Tokens().secretSync().includes('='))
  }
})
