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

proc keyGen(): tuple[pk: PublicKey, sk: SecretKey] =
  var ikm: array[32, byte]
  for b in ikm.mitems:
    b = byte benchRNG.rand(0xFF)
  doAssert ikm.keyGen(result.pk, result.sk)

proc benchFastAggregateVerify*(numKeys, iters: int) =
  ## Verification of N pubkeys signing for 1 message
  let msg = "Mr F was here"

  var validators = newSeq[PublicKey](numKeys)
  var aggSig: AggregateSignature

  for i in 0 ..< numKeys:
    let (pk, sk) = keyGen()
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

when BLS_BACKEND == BLST:
  proc batchVerifyMulti*(numSigs, iters: int) =
    ## Verification of N pubkeys signing for N messages

    var triplets: seq[tuple[pubkey: PublicKey, msg: array[32, byte], sig: Signature]]

    for i in 0 ..< numSigs:
      let (pk, sk) = keyGen()
      var hashedMsg: array[32, byte]
      hashedMsg.bls_sha256_digest("msg" & $i)
      triplets.add (pk, hashedMsg, sk.sign(hashedMsg))

    bench("BLS verif of " & $numSigs & " msgs by "& $numSigs & " pubkeys", iters):
      for i in 0 ..< triplets.len:
        let ok = triplets[i].pubkey.verify(triplets[i].msg, triplets[i].sig)
        doAssert ok

  proc batchVerifyMultiBatchedSerial*(numSigs, iters: int) =
    ## Verification of N pubkeys signing for N messages

    var batch: seq[SignatureSet]

    for i in 0 ..< numSigs:
      let (pk, sk) = keyGen()
      var hashedMsg: array[32, byte]
      hashedMsg.bls_sha256_digest("msg" & $i)
      batch.add((pk, hashedMsg, sk.sign(hashedMsg)))

    var secureBlindingBytes: array[32, byte]
    secureBlindingBytes.bls_sha256_digest("Mr F was here")

    var cache: BatchedBLSVerifierCache

    bench("Serial batch verify " & $numSigs & " msgs by "& $numSigs & " pubkeys (with blinding)", iters):
      secureBlindingBytes.bls_sha256_digest(secureBlindingBytes)
      let ok = cache.batchVerifySerial(batch, secureBlindingBytes)

  proc batchVerifyMultiBatchedParallel*(numSigs, iters: int) =
    ## Verification of N pubkeys signing for N messages

    var batch: seq[SignatureSet]

    for i in 0 ..< numSigs:
      let (pk, sk) = keyGen()
      var hashedMsg: array[32, byte]
      hashedMsg.bls_sha256_digest("msg" & $i)
      batch.add((pk, hashedMsg, sk.sign(hashedMsg)))

    var cache: BatchedBLSVerifierCache
    var secureBlindingBytes: array[32, byte]
    secureBlindingBytes.bls_sha256_digest("Mr F was here")

    bench("Parallel batch verify of " & $numSigs & " msgs by " & $numSigs & " pubkeys (with blinding)", iters):
      secureBlindingBytes.bls_sha256_digest(secureBlindingBytes)
      let ok = cache.batchVerifyParallel(batch, secureBlindingBytes)

when isMainModule:
  benchSign(1000)
  benchVerify(1000)
  benchFastAggregateVerify(numKeys = 128, iters = 10)

  when BLS_BACKEND == BLST:
    # Simulate Block verification
    batchVerifyMulti(numSigs = 6, iters = 10)
    batchVerifyMultiBatchedSerial(numSigs = 6, iters = 10)
    batchVerifyMultiBatchedParallel(numSigs = 6, iters = 10)

    # Simulate 10 blocks verification
    batchVerifyMulti(numSigs = 60, iters = 10)
    batchVerifyMultiBatchedSerial(numSigs = 60, iters = 10)
    batchVerifyMultiBatchedParallel(numSigs = 60, iters = 10)

    # Simulate 30 blocks verification
    batchVerifyMulti(numSigs = 180, iters = 10)
    batchVerifyMultiBatchedSerial(numSigs = 180, iters = 10)
    batchVerifyMultiBatchedParallel(numSigs = 180, iters = 10)
