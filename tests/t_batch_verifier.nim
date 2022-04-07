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
  std/[unittest, random],
  # Status libraries
  taskpools,
  # Public API
  ../blscurve,
  # Internal
  ../blscurve/blst/blst_abi

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

proc hash[T: byte|char](message: openArray[T]): array[32, byte] {.noinit.}=
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

# ---------------------------------------------------------
#
# Malicious forged signatures:
# https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
#
# We call M, PK, S and AS:
# messages, public keys, signatures and aggregated signatures.
#
# We have:
# - PK1 verifying the pair (S1, M1)
# - PK2 verifying the pair (S2, M2)
# - PK1+PK2 verifying the aggregated (S1+S2, M1+M2)
#
# Due to pairing bilinearity, this also means that forged signatures
# S1 + S' and S2 - S' would verify when aggregated
# i.e. PK1+PK2 verifying the aggregated ((S1+S')+(S2-S'), M1+M2)

proc genForgedPair(batch: var seq[SignatureSet],
                   seed1: int, message1: string,
                   seed2: int, message2: string) =
  # Generate (PK1, S1+S', M1)
  # and      (PK2, S2-S', M2)
  # that would pass naive PK1+PK2 aggregate verification.

  let (pk1, sk1) = keyGen(seed1.uint64)
  let hashed1 = hash(message1)
  let sig1 = sk1.sign(hashed1)

  let (pk2, sk2) = keyGen(seed2.uint64)
  let hashed2 = hash(message2)
  let sig2 = sk2.sign(hashed2)

  # Forged signature S'
  let (pkp, skp) = keyGen(uint64(seed1*seed2 + seed1 + seed2))
  let sigp = skp.sign(hash("rekt"))

  # Check that the forged signature can be verified when naively aggregated
  # 1. Create -S'. Note: if P has elliptic affine coordinates (x, y) then -P is (x, -y)
  var neg_sigp = sigp
  let neg_sigp_ptr = cast[ptr blst_p2_affine](neg_sigp.addr)
  neg_sigp_ptr.y.blst_fp2_cneg(neg_sigp_ptr.y, 1)

  # 2. Forge signatures S1+S' and S2-S'
  var forgedSig1s, forgedSig2ns: Signature
  doAssert forgedSig1s.aggregateAll([sig1, sigp])
  doAssert forgedSig2ns.aggregateAll([sig2, cast[Signature](neg_sigp)])

  # 3. Aggregate forged signatures
  var aggForged: Signature
  doAssert aggForged.aggregateAll([forgedSig1s, forgedSig2ns])

  # 4. Naive aggregation
  doAssert aggregateVerify(
    [pk1, pk2],
    [@hashed1, @hashed2],
    aggForged
  ), "The forged aggregate signature should pass naive verification."

  # Now add to a proper batch verification set
  batch.add((pk1, hashed1, forgedSig1s))
  batch.add((pk2, hashed2, forgedSig2ns))

suite "Batch forged signatures":
  var tp = Taskpool.new(numThreads = 4)

  wrappedTest "Single forged pair":
    var cache: BatchedBLSVerifierCache
    var batch: seq[SignatureSet]

    batch.genForgedPair(1, "msg1", 2, "msg2")

    check:
      not tp.batchVerify(cache, batch, fakeRandomBytes)
      not tp.batchVerify(batch, fakeRandomBytes)

  wrappedTest "One forgery among many signatures":
    var cache: BatchedBLSVerifierCache
    var batch: seq[SignatureSet]

    var rng = initRand(1234)

    for i in 0 ..< 16:
      batch.addExample(i, "msg" & $i)
    batch.genForgedPair(1, "msg100", 2, "msg200")

    # Randomize the order
    rng.shuffle(batch)

    check:
      not tp.batchVerify(cache, batch, fakeRandomBytes)
      not tp.batchVerify(batch, fakeRandomBytes)

  tp.shutdown()
