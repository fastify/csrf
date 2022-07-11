'use strict'

/*!
 * @fastify/csrf
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2015 Douglas Christopher Wilson
 * Copyright(c) 2021-2022 Fastify Collaborators
 * MIT Licensed
 */

const crypto = require('crypto')

/**
 * Token generation/verification class.
 *
 * @param {object} [options]
 * @param {number} [options.saltLength=8] The string length of the salt
 * @param {number} [options.secretLength=18] The byte length of the secret key
 * @param {number} [options.validity=0] The maximum milliseconds of validity of this token. 0 disables the check.
 * @param {boolean} [options.userInfo=false] Require userInfo on create() and verify()
 * @public
 */

function Tokens (options) {
  if (!(this instanceof Tokens)) {
    return new Tokens(options)
  }

  const opts = options || {}

  const saltLength = opts.saltLength !== undefined
    ? opts.saltLength
    : 8

  if (typeof saltLength !== 'number' || !isFinite(saltLength) || saltLength < 1) {
    throw new TypeError('option saltLength must be finite number > 1')
  }

  const secretLength = opts.secretLength !== undefined
    ? opts.secretLength
    : 18

  if (typeof secretLength !== 'number' || !isFinite(secretLength) || secretLength < 1) {
    throw new TypeError('option secretLength must be finite number > 1')
  }

  const validity = opts.validity !== undefined
    ? opts.validity
    : 0

  if (typeof validity !== 'number' || !isFinite(validity) || validity < 0) {
    throw new TypeError('option validity must be finite number > 0')
  }

  const userInfo = opts.userInfo !== undefined
    ? opts.userInfo
    : false

  if (typeof userInfo !== 'boolean') {
    throw new TypeError('option userInfo must be a boolean')
  }

  this.saltLength = saltLength
  this.saltGenerator = saltGenerator(saltLength)
  this.secretLength = secretLength
  this.secretGenerator = secretGenerator(secretLength)
  this.validity = validity
  this.userInfo = userInfo
}

/**
 * Create a new CSRF token.
 *
 * @param {string} secret The secret for the token.
 * @param {?string} userInfo The userInfo for the token.
 * @returns {string}
 * @public
 */

Tokens.prototype.create = function create (secret, userInfo) {
  if (!secret || typeof secret !== 'string') {
    throw new TypeError('argument secret is required')
  }
  const date = this.validity > 0 ? Date.now() : null

  if (this.userInfo) {
    if (typeof userInfo !== 'string') {
      throw new TypeError('argument userInfo is required to be a string')
    }
  }

  return this._tokenize(secret, this.saltGenerator(), date, userInfo)
}

/**
 * Create a new secret key.
 *
 * @param {function} [callback]
 * @returns {string}
 * @public
 */

Tokens.prototype.secret = function secret (callback) {
  if (callback !== undefined && typeof callback !== 'function') {
    throw new TypeError('argument callback must be a function')
  }

  if (!callback && !global.Promise) {
    throw new TypeError('argument callback is required')
  }

  if (callback) {
    callback(null, this.secretGenerator())
    return
  }

  return Promise.resolve(this.secretGenerator())
}

/**
 * Create a new secret key synchronously.
 * @returns {string}
 * @public
 */

Tokens.prototype.secretSync = function secretSync () {
  return this.secretGenerator()
}

/**
 * Tokenize a secret, salt, date and userInfo.
 * @returns {string}
 * @private
 */

Tokens.prototype._tokenize = Buffer.isEncoding('base64url')
  ? function _tokenize (secret, salt, date, userInfo) {
    let toHash = ''

    if (date !== null) {
      toHash += date.toString(36) + '-'
    }

    if (typeof userInfo === 'string') {
      toHash += crypto
        .createHash('sha1')
        .update(userInfo)
        .digest('base64url')
        .replace(MINUS_GLOBAL_REGEXP, '_') + '-'
    }

    toHash += salt

    return toHash + '-' + crypto
      .createHash('sha1')
      .update(toHash + '-' + secret, 'ascii')
      .digest('base64url')
  }
  : function _tokenize (secret, salt, date, userInfo) {
    let toHash = ''

    if (date !== null) {
      toHash += date.toString(36) + '-'
    }

    if (typeof userInfo === 'string') {
      toHash += crypto
        .createHash('sha1')
        .update(userInfo)
        .digest('base64')
        .replace(PLUS_SLASH_GLOBAL_REGEXP, '_')
        .replace(EQUAL_GLOBAL_REGEXP, '') + '-'
    }

    toHash += salt

    return toHash + '-' + crypto
      .createHash('sha1')
      .update(toHash + '-' + secret, 'ascii')
      .digest('base64')
      .replace(PLUS_GLOBAL_REGEXP, '-')
      .replace(SLASH_GLOBAL_REGEXP, '_')
      .replace(EQUAL_GLOBAL_REGEXP, '')
  }

/**
 * Verify if a given token is valid for a given secret.
 *
 * @param {string} secret The secret for the token.
 * @param {string} token The token itself.s
 * @param {?string} userInfo The userInfo for the token.
 * @returns {string}
 * @public
 */

Tokens.prototype.verify = function verify (secret, token, userInfo) {
  if (!secret || typeof secret !== 'string') {
    return false
  }

  if (!token || typeof token !== 'string') {
    return false
  }

  if (this.userInfo && (!userInfo || typeof userInfo !== 'string')) {
    return false
  }

  let curIdx = 0
  let nextIdx = token.indexOf('-')
  if (nextIdx === -1) {
    return false
  }

  let date = null

  if (this.validity > 0) {
    date = parseInt(token.slice(curIdx, nextIdx), 36)

    if (Date.now() - date > this.validity) {
      return false
    }

    curIdx = nextIdx + 1
    nextIdx = token.indexOf('-', curIdx)

    if (nextIdx === -1) {
      return false
    }
  }

  if (this.userInfo) {
    // we skip the userInfo part, this will be verified with the hashing
    curIdx = nextIdx + 1
    nextIdx = token.indexOf('-', curIdx)

    if (nextIdx === -1) {
      return false
    }
  }

  const salt = token.slice(curIdx, nextIdx)

  const actual = Buffer.from(token)
  const expected = Buffer.from(this._tokenize(secret, salt, date, userInfo))

  // to avoid the exposure if the provided value has the correct length, we call
  // timingSafeEqual with the actual value. The additional length check itself is
  // timing safe.
  return crypto.timingSafeEqual(
    actual.length === expected.length
      ? expected
      : actual,
    actual
  ) && actual.length === expected.length
}

const EQUAL_GLOBAL_REGEXP = /=/g
const PLUS_GLOBAL_REGEXP = /\+/g
const SLASH_GLOBAL_REGEXP = /\//g
const MINUS_GLOBAL_REGEXP = /-/g
const PLUS_SLASH_GLOBAL_REGEXP = /[+/]/g

function secretGenerator (secretLength) {
  const fnBody = []

  fnBody.push('const randomInt = crypto.randomInt;')
  fnBody.push('const base64url = \'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_\'.split(\'\');')
  fnBody.push('return function () {')
  const secret = []
  for (let i = 0; i < ((secretLength * 1.5) | 0); ++i) secret.push('base64url[randomInt(0, 64)]')
  fnBody.push('return ' + secret.join('+'))
  fnBody.push('}')
  return new Function('crypto', fnBody.join(''))(crypto) // eslint-disable-line no-new-func
}

function saltGenerator (saltLength) {
  const fnBody = []

  fnBody.push('const base62 = \'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\'.split(\'\');')
  fnBody.push('return function () {')
  const salt = []
  for (let i = 0; i < saltLength; ++i) salt.push('base62[(62 * Math.random()) | 0]')
  fnBody.push('return ' + salt.join('+'))
  fnBody.push('}')
  return new Function(fnBody.join(''))() // eslint-disable-line no-new-func
}

module.exports = Tokens
module.exports.default = Tokens
module.exports.Tokens = Tokens
