# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  std/random,
  ../blscurve,
  ./bench_templates

# ############################################################
#
#             Benchmark of BLS Signature Scheme
#                   (Boneh-Lynn-Schacham)
#
# ############################################################

var benchRNG = initRand(0xFACADE)

proc benchSign*(iters: int) =
  let msg = "Mr F was here"

  var pk: PublicKey
  var sk: SecretKey
  var ikm: array[32, byte]

  for b in ikm.mitems:
    b = byte benchRNG.rand(0xFF)
  doAssert ikm.keyGen(pk, sk)

  bench("BLS signature", iters):
    let sig = sk.sign(msg)

proc benchVerify*(iters: int) =
  let msg = "Mr F was here"

  var pk: PublicKey
  var sk: SecretKey
  var ikm: array[32, byte]

  for b in ikm.mitems:
    b = byte benchRNG.rand(0xFF)
  doAssert ikm.keyGen(pk, sk)

  let sig = sk.sign(msg)

  bench("BLS verification", iters):
    let valid = pk.verify(msg, sig)
    # doAssert valid

proc benchFastAggregateVerify*(numKeys, iters: int) =
  let msg = "Mr F was here"

  var validators = newSeq[PublicKey](numKeys)
  var aggSig: AggregateSignature

  for i in 0 ..< numKeys:
    var pk: PublicKey
    var sk: SecretKey
    var ikm: array[32, byte]

    for b in ikm.mitems:
      b = byte benchRNG.rand(0xFF)
    doAssert ikm.keyGen(pk, sk)

    validators[i] = pk

    let sig = sk.sign(msg)

    if i == 0:
      aggSig.init(sig)
    else:
      aggSig.aggregate(sig)

  var finalSig: Signature
  finalSig.finish(aggSig)

  bench("BLS agg verif of 1 msg by " & $numKeys & " pubkeys", iters):
    let valid = validators.fastAggregateVerify(msg, finalSig)
    doAssert valid

when isMainModule:
  benchSign(1000)
  benchVerify(1000)
  benchFastAggregateVerify(numKeys = 128, iters = 10)
