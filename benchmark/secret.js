/**
 * Module dependencies.
 */

const benchmark = require('benchmark')
const benchmarks = require('beautify-benchmark')
const Tokens = require('..')

/**
* Globals for benchmark.js
*/

const tokens = new Tokens()

const suite = new benchmark.Suite()

suite.add('secretSync', function () {
  tokens.secretSync()
}, {
  minSamples: 100
})

suite.add('secret - callback', function (deferred) {
  tokens.secret(function () { deferred.resolve() })
}, {
  minSamples: 100,
  defer: true,
  delay: 0
})

suite.add('secret - promise', function (deferred) {
  tokens.secret().then(function (secret) { deferred.resolve() })
}, {
  minSamples: 100,
  defer: true,
  delay: 0
})

suite.on('start', function onCycle (event) {
  process.stdout.write('  secret\n\n')
})

suite.on('cycle', function onCycle (event) {
  benchmarks.add(event.target)
})

suite.on('complete', function onComplete () {
  benchmarks.log()
})

suite.run({ async: false, delay: 0 })
