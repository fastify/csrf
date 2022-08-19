'use strict'

const test = require('tap').test
const Tokens = require('..')

test('.create() and verify() with validity: should return `true` with valid tokens', t => {
  t.plan(1)

  const secret = new Tokens().secretSync()
  const token = new Tokens({ validity: 3600 }).create(secret)

  t.equal(new Tokens({ validity: 3600 }).verify(secret, token), true)
})

test('.create() and verify() with validity: should return `false` if current time is outside the validity interval', t => {
  t.plan(1)

  const fn = Date.now
  const now = Date.now()
  t.teardown(() => { Date.now = fn })

  const secret = new Tokens().secretSync()
  Date.now = function () { return now }
  const token = new Tokens({ validity: 3600 }).create(secret)

  Date.now = function () { return now + 3601 }
  t.equal(new Tokens({ validity: 3600 }).verify(secret, token), false)
})

test('.create() and verify() with validity: should return `true` if current time is at the max of the validity interval', t => {
  t.plan(1)

  const fn = Date.now
  const now = Date.now()
  t.teardown(() => { Date.now = fn })

  Date.now = function () { return now }
  const secret = new Tokens().secretSync()
  Date.now = function () { return now + 3600 }
  const token = new Tokens({ validity: 3600 }).create(secret)

  t.equal(new Tokens({ validity: 3600 }).verify(secret, token), true, { secret, token, now })
})

test('.create() and verify() with validity: should return `false` for tokens with no date', t => {
  t.plan(1)

  const secret = new Tokens().secretSync()
  let token = new Tokens({ validity: 3600 }).create(secret)
  token = token.substring(token.indexOf('-') + 1)

  t.equal(new Tokens({ validity: 3600 }).verify(secret, token), false)
})

test('.create() and verify() with user info: should return `true` with valid tokens', t => {
  t.plan(1)

  const secret = new Tokens().secretSync()
  const token = new Tokens({ userInfo: true }).create(secret, 'foobar')

  t.equal(new Tokens({ userInfo: true }).verify(secret, token, 'foobar'), true)
})

test('.create() and verify() with user info: should return `false` if userInfo does not match', t => {
  t.plan(1)

  const secret = new Tokens().secretSync()
  const token = new Tokens({ userInfo: true }).create(secret, 'foo')

  t.equal(new Tokens({ userInfo: true }).verify(secret, token, 'foobar'), false)
})

test('.create() and verify() with user info: should return `false` if userInfo is not set in verify', t => {
  t.plan(1)

  const secret = new Tokens().secretSync()
  const token = new Tokens({ userInfo: true }).create(secret, 'foo')

  t.equal(new Tokens({ userInfo: true }).verify(secret, token), false)
})

test('.create() and verify() with user info: should return `false` if userInfo is not a string in verify', t => {
  t.plan(1)

  const secret = new Tokens().secretSync()
  const token = new Tokens({ userInfo: true }).create(secret, 'foo')

  t.equal(new Tokens({ userInfo: true }).verify(secret, token, {}), false)
})

test('.create() and verify() with user info: should return `false` for tokens with no userInfo', t => {
  t.plan(1)

  const secret = new Tokens().secretSync()
  let token = new Tokens({ userInfo: true }).create(secret, 'foo')
  token = token.substring(token.indexOf('-') + 1)

  t.equal(new Tokens({ userInfo: true }).verify(secret, token, 'foo'), false)
})
