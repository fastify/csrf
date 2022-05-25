/*!
 * csrf
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2015 Douglas Christopher Wilson
 * Copyright(c) 2021-2022 Fastify Collaborators
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 * @private
 */

const rndm = require('rndm')
const uid = require('uid-safe')
const compare = require('tsscmp')
const crypto = require('crypto')

/**
 * Module variables.
 * @private
 */

const EQUAL_GLOBAL_REGEXP = /=/g
const PLUS_GLOBAL_REGEXP = /\+/g
const SLASH_GLOBAL_REGEXP = /\//g
const MINUS_GLOBAL_REGEXP = /-/g

/**
 * Module exports.
 * @public
 */

module.exports = Tokens

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
  this.secretLength = secretLength
  this.validity = validity
  this.userInfo = userInfo
}

/**
 * Create a new CSRF token.
 *
 * @param {string} secret The secret for the token.
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

  return this._tokenize(secret, rndm(this.saltLength), date, userInfo)
}

/**
 * Create a new secret key.
 *
 * @param {function} [callback]
 * @public
 */

Tokens.prototype.secret = function secret (callback) {
  return uid(this.secretLength, callback)
}

/**
 * Create a new secret key synchronously.
 * @public
 */

Tokens.prototype.secretSync = function secretSync () {
  return uid.sync(this.secretLength)
}

/**
 * Tokenize a secret, salt, date and userInfo.
 * @private
 */

Tokens.prototype._tokenize = function tokenize (secret, salt, date, userInfo) {
  let toHash = ''

  if (date !== null) {
    toHash += date.toString(36) + '-'
  }

  if (typeof userInfo === 'string') {
    // we hash the userInfo to ensure it's encoded properly and to have a fixed length
    userInfo = hash(userInfo).replace(MINUS_GLOBAL_REGEXP, '_')
    toHash += userInfo + '-'
  }

  toHash += salt

  return toHash + '-' + hash(toHash + '-' + secret)
}

/**
 * Verify if a given token is valid for a given secret.
 *
 * @param {string} secret
 * @param {string} token
 * @param {string} userInfo
 * @public
 */

Tokens.prototype.verify = function verify (secret, token, userInfo) {
  if (!secret || typeof secret !== 'string') {
    return false
  }

  if (!token || typeof token !== 'string') {
    return false
  }

  let index = token.indexOf('-')
  const toCompare = token
  let date = null

  if (index === -1) {
    return false
  }

  if (this.validity > 0) {
    date = parseInt(token.substr(0, index), 36)

    if (Date.now() - date > this.validity) {
      return false
    }

    token = token.substr(index + 1)
    index = token.indexOf('-')

    if (index === -1) {
      return false
    }
  }

  if (this.userInfo) {
    // validate the optional argument, it is required
    // only if this.userInfo is true
    if (!userInfo || typeof userInfo !== 'string') {
      return false
    }

    // we skip the userInfo part, this will be
    // verified with the hashing
    token = token.substr(index + 1)
    index = token.indexOf('-')

    if (index === -1) {
      return false
    }
  }

  const salt = token.substr(0, index)
  const expected = this._tokenize(secret, salt, date, userInfo)

  return compare(toCompare, expected)
}

/**
 * Hash a string with SHA1, returning url-safe base64
 * @param {string} str
 * @private
 */

function hash (str) {
  return crypto
    .createHash('sha1')
    .update(str, 'ascii')
    .digest('base64')
    .replace(PLUS_GLOBAL_REGEXP, '-')
    .replace(SLASH_GLOBAL_REGEXP, '_')
    .replace(EQUAL_GLOBAL_REGEXP, '')
}
