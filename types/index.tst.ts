/* eslint-disable no-new -- Testing constructor types, so no need to assign */
/// <reference types="node" />
import { expect } from 'tstyche'
import { Tokens } from '..'

Tokens()
new Tokens()
Tokens({})
new Tokens({})
Tokens({ algorithm: 'sha1' })
Tokens({ algorithm: 'sha256' })
Tokens({ saltLength: 10 })
Tokens({ secretLength: 10 })
Tokens({ userInfo: true })
Tokens({ validity: 10000 })
Tokens({ hmacKey: 'foo' })
new Tokens({ saltLength: 10 })
new Tokens({ secretLength: 10 })
new Tokens({ userInfo: true })
new Tokens({ validity: 10000 })

// @ts-expect-error!
Tokens('secret')
// @ts-expect-error!
new Tokens('secret')

// @ts-expect-error!
new Tokens({}).create('secret', 'userInfo')
// @ts-expect-error!
new Tokens({ userInfo: false }).create('secret', 'userInfo')
// @ts-expect-error!
new Tokens({ userInfo: true }).create('secret')

// @ts-expect-error!
new Tokens({}).verify('secret', 'token', 'userinfo')
// @ts-expect-error!
new Tokens({ userInfo: false }).verify('secret', 'token', 'userInfo')
// @ts-expect-error!
new Tokens({ userInfo: true }).verify('secret', 'token')

// @ts-expect-error!
new Tokens({ hmacKey: 123 })

expect(Tokens().secret()).type.toBe<Promise<string>>()
expect(new Tokens().secret()).type.toBe<Promise<string>>()

expect(
  Tokens().secret((err, secret) => {
    expect(err).type.toBe<Error | null>()
    expect(secret).type.toBe<string>()
  })
).type.toBe<void>()

expect(
  new Tokens().secret((err, secret) => {
    expect(err).type.toBe<Error | null>()
    expect(secret).type.toBe<string>()
  })
).type.toBe<void>()

expect(Tokens().secretSync()).type.toBe<string>()
expect(new Tokens().secretSync()).type.toBe<string>()
