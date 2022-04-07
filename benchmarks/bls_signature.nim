# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  std/[random, cpuinfo, os, strutils],
  taskpools,
  ../blscurve,
  ./bench_templates

# ############################################################
#
#             Benchmark of BLS Signature Scheme
#                   (Boneh-Lynn-Schacham)
#
# ############################################################

var benchRNG = initRand(0xFACADE)

proc benchDeserPubkey*(iters: int) =
  const seckey = "00000000000000000000000000000000000000000000000000000000000003e8"
  var
    sk{.noinit.}: SecretKey
    pk{.noinit.}: PublicKey
    pk_comp{.noinit.}: array[48, byte]

  let ok = sk.fromHex(seckey)
  doAssert ok
  let ok2 = pk.publicFromSecret(sk)
  doAssert ok2

  # Serialize compressed
  doAssert pk_comp.serialize(pk)

  var pk2{.noinit.}: PublicKey

  bench("Pubkey deserialization (full checks)", iters):
    doAssert pk2.fromBytes(pk_comp)

proc benchDeserPubkeyKnownOnCurve*(iters: int) =
  const seckey = "00000000000000000000000000000000000000000000000000000000000003e8"
  var
    sk{.noinit.}: SecretKey
    pk{.noinit.}: PublicKey
    pk_comp{.noinit.}: array[48, byte]

  let ok = sk.fromHex(seckey)
  doAssert ok
  let ok2 = pk.publicFromSecret(sk)
  doAssert ok2

  # Serialize compressed
  doAssert pk_comp.serialize(pk)

  var pk2{.noinit.}: PublicKey

  when BLS_BACKEND == BLST:
    bench("Pubkey deserialization (known on curve)", iters):
      doAssert pk2.fromBytesKnownOnCurve(pk_comp)

proc benchDeserSig*(iters: int) =
  const seckey = "00000000000000000000000000000000000000000000000000000000000003e8"
  const msg = "abcdef0123456789"

  var
    sk{.noinit.}: SecretKey
    pk{.noinit.}: PublicKey
    sig_comp{.noinit.}: array[96, byte]

  let ok = sk.fromHex(seckey)
  doAssert ok
  let ok2 = pk.publicFromSecret(sk)
  doAssert ok2

  let sig = sk.sign(msg)

  # Serialize compressed
  doAssert sig_comp.serialize(sig)

  var sig2{.noinit.}: Signature

  bench("Signature deserialization (full checks)", iters):
    doAssert sig2.fromBytes(sig_comp)

proc benchDeserSigKnownOnCurve*(iters: int) =
  const seckey = "00000000000000000000000000000000000000000000000000000000000003e8"
  const msg = "abcdef0123456789"

  var
    sk{.noinit.}: SecretKey
    pk{.noinit.}: PublicKey
    sig_comp{.noinit.}: array[96, byte]

  let ok = sk.fromHex(seckey)
  doAssert ok
  let ok2 = pk.publicFromSecret(sk)
  doAssert ok2

  let sig = sk.sign(msg)

  # Serialize compressed
  doAssert sig_comp.serialize(sig)

  var sig2{.noinit.}: Signature

  when BLS_BACKEND == BLST:
    bench("Signature deserialization (known on curve)", iters):
      doAssert sig2.fromBytesKnownOnCurve(sig_comp)

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
      doAssert ok

  proc batchVerifyMultiBatchedParallel*(numSigs, iters, nthreads: int) =
    ## Verification of N pubkeys signing for N messages

    var tp: Taskpool
    var batch: seq[SignatureSet]
    tp = Taskpool.new(numThreads = nthreads)

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
      let ok = tp.batchVerifyParallel(cache, batch, secureBlindingBytes)
      doAssert ok

when isMainModule:
  benchDeserPubkey(1000)
  benchDeserSig(1000)
  benchSign(1000)
  benchVerify(1000)
  benchFastAggregateVerify(numKeys = 128, iters = 10)

  when BLS_BACKEND == BLST:
    benchDeserPubkeyKnownOnCurve(1000)
    benchDeserSigKnownOnCurve(1000)

    var nthreads: int
    if existsEnv"TP_NUM_THREADS":
      nthreads = getEnv"TP_NUM_THREADS".parseInt()
    else:
      nthreads = countProcessors()

    # Simulate Block verification (at most 6 signatures per block)
    batchVerifyMulti(numSigs = 6, iters = 10)
    batchVerifyMultiBatchedSerial(numSigs = 6, iters = 10)
    batchVerifyMultiBatchedParallel(numSigs = 6, iters = 10, nthreads)

    # Simulate 10 blocks verification
    batchVerifyMulti(numSigs = 60, iters = 10)
    batchVerifyMultiBatchedSerial(numSigs = 60, iters = 10)
    batchVerifyMultiBatchedParallel(numSigs = 60, iters = 10, nthreads)

    # Simulate 30 blocks verification
    batchVerifyMulti(numSigs = 180, iters = 10)
    batchVerifyMultiBatchedSerial(numSigs = 180, iters = 10)
    batchVerifyMultiBatchedParallel(numSigs = 180, iters = 10, nthreads)

    echo "\nUsing nthreads = ", nthreads, ". The number of threads can be changed with TP_NUM_THREADS environment variable."
