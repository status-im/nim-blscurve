# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  # Standard library
  std/unittest,
  # Status libraries
  taskpools,
  # Public API
  ../blscurve

# Tests for batch verification

template wrappedTest(desc: string, body: untyped): untyped =
  ## Wrap test in a proc to avoid having globals everywhere
  ## ballooning the test BSS space usage
  ## properly test destructors/GC/try-finally, ...
  ## aliasing
  ## and optimizations (that don't apply to globals)
  test desc:
    proc wTest() =
      body

    wTest()

proc keyGen(seed: uint64): tuple[pubkey: PublicKey, seckey: SecretKey] =
  var ikm: array[32, byte]
  ikm[0 ..< 8] = cast[array[8, byte]](seed)
  let ok = ikm.keyGen(result.pubkey, result.seckey)
  doAssert ok

proc hash[T: byte|char](message: openarray[T]): array[32, byte] {.noInit.}=
  result.bls_sha256_digest(message)

proc addExample(batch: var seq[SignatureSet], seed: int, message: string) =
  let (pubkey, seckey) = keyGen(seed.uint64)
  let hashed = hash(message)
  let sig = seckey.sign(hashed)
  batch.add((pubkey, hashed, sig))

# Test strategy
# As we use a tree algorithm we want to test
# - a single signature set
# - a signature set of size 2^n-1
# - a signature set of size 2^n
# - a signature set of size 2^n+1
# for boundary conditions
# we also want to test forged signature sets
# that would pass grouped verification
# https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407/16

let fakeRandomBytes = hash"Mr F was here"

suite "Batch verification":
  var tp = Taskpool.new(numThreads = 4)

  wrappedTest "Verify a single (pubkey, message, signature) triplet":
    let msg = hash"message"
    let (pubkey, seckey) = keyGen(123)
    let sig = seckey.sign(msg)

    var cache: BatchedBLSVerifierCache
    var batch: seq[SignatureSet]

    batch.add((pubkey, msg, sig))
    check:
      tp.batchVerify(cache, batch, fakeRandomBytes)
      tp.batchVerify(batch, fakeRandomBytes)

  wrappedTest "Verify 2 (pubkey, message, signature) triplets":
    var cache: BatchedBLSVerifierCache
    var batch: seq[SignatureSet]

    batch.addExample(1, "msg1")
    batch.addExample(2, "msg2")

    check:
      tp.batchVerify(cache, batch, fakeRandomBytes)
      tp.batchVerify(batch, fakeRandomBytes)

  wrappedTest "Verify 2^4 - 1 = 15 (pubkey, message, signature) triplets":
    var cache: BatchedBLSVerifierCache
    var batch: seq[SignatureSet]

    for i in 0 ..< 15:
      batch.addExample(i, "msg" & $i)

    check:
      tp.batchVerify(cache, batch, fakeRandomBytes)
      tp.batchVerify(batch, fakeRandomBytes)

  wrappedTest "Verify 2^4 = 16 (pubkey, message, signature) triplets":
    var cache: BatchedBLSVerifierCache
    var batch: seq[SignatureSet]

    for i in 0 ..< 16:
      batch.addExample(i, "msg" & $i)

    check:
      tp.batchVerify(cache, batch, fakeRandomBytes)
      tp.batchVerify(batch, fakeRandomBytes)

  wrappedTest "Verify 2^4 + 1 = 17 (pubkey, message, signature) triplets":
    var cache: BatchedBLSVerifierCache
    var batch: seq[SignatureSet]

    for i in 0 ..< 17:
      batch.addExample(i, "msg" & $i)

    check:
      tp.batchVerify(cache, batch, fakeRandomBytes)
      tp.batchVerify(batch, fakeRandomBytes)

  wrappedTest "Wrong signature":
    let msg1 = hash"msg1"
    let msg2 = hash"msg2"
    let (pubkey1, seckey1) = keyGen(1)
    let sig1 = seckey1.sign(msg1)

    let (pubkey2, seckey2) = keyGen(2)

    var cache: BatchedBLSVerifierCache
    var batch: seq[SignatureSet]

    batch.add((pubkey1, msg1, sig1))
    batch.add((pubkey2, msg2, sig1)) # <--- wrong signature
    check:
      not tp.batchVerify(cache, batch, fakeRandomBytes)
      not tp.batchVerify(batch, fakeRandomBytes)

  tp.shutdown()
