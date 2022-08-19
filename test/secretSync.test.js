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
