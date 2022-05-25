'use strict'

const assert = require('assert')
const Tokens = require('..')

// Add Promise to mocha's global list
// eslint-disable-next-line no-self-assign
global.Promise = global.Promise

describe('Tokens', function () {
  describe('options', function () {
    describe('saltLength', function () {
      it('should reject non-numbers', function () {
        assert.throws(Tokens.bind(null, { saltLength: 'bogus' }),
          /option saltLength/)
      })

      it('should reject NaN', function () {
        assert.throws(Tokens.bind(null, { saltLength: NaN }),
          /option saltLength/)
      })

      it('should reject Infinity', function () {
        assert.throws(Tokens.bind(null, { saltLength: Infinity }),
          /option saltLength/)
      })
    })

    describe('secretLength', function () {
      it('should reject non-numbers', function () {
        assert.throws(Tokens.bind(null, { secretLength: 'bogus' }),
          /option secretLength/)
      })

      it('should reject NaN', function () {
        assert.throws(Tokens.bind(null, { secretLength: NaN }),
          /option secretLength/)
      })

      it('should reject Infinity', function () {
        assert.throws(Tokens.bind(null, { secretLength: Infinity }),
          /option secretLength/)
      })

      it('should generate secret with specified byte length', function () {
        // 3 bytes = 4 base-64 characters
        // 4 bytes = 6 base-64 characters
        assert.strictEqual(Tokens({ secretLength: 3 }).secretSync().length, 4)
        assert.strictEqual(Tokens({ secretLength: 4 }).secretSync().length, 6)
      })
    })

    describe('validity', function () {
      it('should reject non-numbers', function () {
        assert.throws(Tokens.bind(null, { validity: 'bogus' }),
          /option validity/)
      })

      it('should reject NaN', function () {
        assert.throws(Tokens.bind(null, { validity: NaN }),
          /option validity/)
      })

      it('should reject Infinity', function () {
        assert.throws(Tokens.bind(null, { validity: Infinity }),
          /option validity/)
      })
    })

    describe('userInfo', function () {
      it('should reject non-booleans', function () {
        assert.throws(Tokens.bind(null, { userInfo: 'bogus' }),
          /option userInfo/)
      })
    })
  })

  describe('.create(secret)', function () {
    before(function () {
      this.tokens = new Tokens()
      this.secret = this.tokens.secretSync()
    })

    it('should require secret', function () {
      assert.throws(function () {
        this.tokens.create()
      }.bind(this), /argument secret.*required/)
    })

    it('should reject non-string secret', function () {
      assert.throws(function () {
        this.tokens.create(42)
      }.bind(this), /argument secret.*required/)
    })

    it('should reject empty string secret', function () {
      assert.throws(function () {
        this.tokens.create('')
      }.bind(this), /argument secret.*required/)
    })

    it('should create a token', function () {
      const token = this.tokens.create(this.secret)
      assert.ok(typeof token === 'string')
    })

    it('should always be the same length', function () {
      const token = this.tokens.create(this.secret)
      assert.ok(token.length > 0)

      for (let i = 0; i < 1000; i++) {
        assert.strictEqual(this.tokens.create(this.secret).length, token.length)
      }
    })

    it('should not contain /, +, or =', function () {
      for (let i = 0; i < 1000; i++) {
        const token = this.tokens.create(this.secret)
        assert(!~token.indexOf('/'))
        assert(!~token.indexOf('+'))
        assert(!~token.indexOf('='))
      }
    })
  })

  describe('.secret(callback)', function () {
    before(function () {
      this.tokens = new Tokens()
    })

    it('should reject bad callback', function () {
      assert.throws(function () {
        this.tokens.secret(42)
      }.bind(this), /argument callback/)
    })

    it('should create a secret', function (done) {
      this.tokens.secret(function (err, secret) {
        assert.ifError(err)
        assert.ok(typeof secret === 'string')
        assert.ok(secret.length > 0)
        done()
      })
    })
  })

  describe('.secret()', function () {
    before(function () {
      this.tokens = new Tokens()
    })

    describe('with global Promise', function () {
      before(function () {
        global.Promise = Promise
      })

      after(function () {
        global.Promise = undefined
      })

      it('should create a secret', function () {
        return this.tokens.secret().then(function (secret) {
          assert.ok(typeof secret === 'string')
          assert.ok(secret.length > 0)
        })
      })
    })

    describe('without global Promise', function () {
      before(function () {
        global.Promise = undefined
      })

      after(function () {
        global.Promise = Promise
      })

      it('should require callback', function () {
        assert.throws(function () {
          this.tokens.secret()
        }.bind(this), /argument callback.*required/)
      })

      it('should reject bad callback', function () {
        assert.throws(function () {
          this.tokens.secret(42)
        }.bind(this), /argument callback/)
      })
    })
  })

  describe('.secretSync()', function () {
    before(function () {
      this.tokens = new Tokens()
    })

    it('should create a secret', function () {
      const secret = this.tokens.secretSync()
      assert.ok(typeof secret === 'string')
      assert.ok(secret.length > 0)
    })
  })

  describe('.verify(secret, token)', function () {
    before(function () {
      this.tokens = new Tokens()
      this.secret = this.tokens.secretSync()
    })

    it('should return `true` with valid tokens', function () {
      const token = this.tokens.create(this.secret)
      assert.ok(this.tokens.verify(this.secret, token))
    })

    it('should return `false` with invalid tokens', function () {
      const token = this.tokens.create(this.secret)
      assert.ok(!this.tokens.verify(this.tokens.secretSync(), token))
      assert.ok(!this.tokens.verify('asdfasdfasdf', token))
    })

    it('should return `false` with invalid secret', function () {
      assert.ok(!this.tokens.verify())
      assert.ok(!this.tokens.verify([]))
    })

    it('should return `false` with invalid tokens', function () {
      assert(!this.tokens.verify(this.secret, undefined))
      assert(!this.tokens.verify(this.secret, []))
      assert(!this.tokens.verify(this.secret, 'hi'))
    })
  })

  describe('.create() and verify() with validity', function () {
    before(function () {
      this.tokens = new Tokens({
        validity: 60 * 60
      })
      this.secret = this.tokens.secretSync()
    })

    it('should return `true` with valid tokens', function () {
      const token = this.tokens.create(this.secret)
      assert.ok(this.tokens.verify(this.secret, token))
    })

    it('should return `false` if current time is outside the validity interval', function () {
      const token = this.tokens.create(this.secret)
      const now = Date.now()
      const fn = Date.now
      Date.now = function () { return now + 1 + 60 * 60 }
      const valid = this.tokens.verify(this.secret, token)
      Date.now = fn
      assert.ok(!valid)
    })

    it('should return `true` if current time is at the max of the validity interval', function () {
      const token = this.tokens.create(this.secret)
      const now = Date.now()
      const fn = Date.now
      Date.now = function () { return now + 60 * 60 }
      const valid = this.tokens.verify(this.secret, token)
      Date.now = fn
      assert.ok(valid)
    })

    it('should return `false` for tokens with no date', function () {
      let token = this.tokens.create(this.secret)
      token = token.substring(token.indexOf('-') + 1)
      assert.ok(!this.tokens.verify(this.secret, token))
    })
  })

  describe('.create() and verify() with user info', function () {
    before(function () {
      this.tokens = new Tokens({
        userInfo: true
      })
      this.secret = this.tokens.secretSync()
    })

    it('should return `true` with valid tokens', function () {
      const token = this.tokens.create(this.secret, 'foobar')
      assert.ok(this.tokens.verify(this.secret, token, 'foobar'))
    })

    it('should return `false` if userInfo does not match', function () {
      const token = this.tokens.create(this.secret, 'foo')
      assert.ok(!this.tokens.verify(this.secret, token, 'foobar'))
    })

    it('should return `false` if userInfo is not set in verify', function () {
      const token = this.tokens.create(this.secret, 'foo')
      assert.ok(!this.tokens.verify(this.secret, token))
    })

    it('should return `false` if userInfo is not a string in verify', function () {
      const token = this.tokens.create(this.secret, 'foo')
      assert.ok(!this.tokens.verify(this.secret, token, {}))
    })

    it('should reject undefined string userInfo (create)', function () {
      assert.throws(function () {
        this.tokens.create(this.secret)
      }.bind(this), /argument userInfo.*required/)
    })

    it('should return `false` for tokens with no userInfo', function () {
      let token = this.tokens.create(this.secret, 'foo')
      token = token.substring(token.indexOf('-') + 1)
      assert.ok(!this.tokens.verify(this.secret, token, 'foo'))
    })
  })
})
