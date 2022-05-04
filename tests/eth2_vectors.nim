# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Test implementation of Cipher Suite BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_POP_
# against Eth2 v0.12.0 vectors

import
  # Standard library
  std/[json, strutils, os, unittest],
  # Status libraries
  stew/byteutils,
  # Public API
  ../blscurve, ../blscurve/bls_sig_min_pubkey,
  # Test helpers
  ./test_locator

when compileOption("threads"):
  import taskpools

type InOut = enum
  Input
  Output

# Eth2 vectors do not include proof-of-possession data.
# By adding proof data here, we can leverage the existing tests to also cover proof-of-possession functionality.
# See https://github.com/ethereum/consensus-specs/blob/dev/tests/generators/bls/main.py#L45-L51
const knownSeckeys = [
  "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
  "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
  "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
]
let knownPubkeys = [
  "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
  "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
  "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
]
let knownProofs = [
  "b803eb0ed93ea10224a73b6b9c725796be9f5fefd215ef7a5b97234cc956cf6870db6127b7e4d824ec62276078e787db05584ce1adbf076bc0808ca0f15b73d59060254b25393d95dfc7abe3cda566842aaedf50bbb062aae1bbb6ef3b1f77e1",
  "88bb31b27eae23038e14f9d9d1b628a39f5881b5278c3c6f0249f81ba0deb1f68aa5f8847854d6554051aa810fdf1cdb02df4af7a5647b1aa4afb60ec6d446ee17af24a8a50876ffdaf9bf475038ec5f8ebeda1c1c6a3220293e23b13a9a5d26",
  "88873ea58f5017a33facc9bf04efaf5e2f34f7bc9ce564d0481dd469326c04ef43552f50e99de8a13315dcd37a4fb9ef036d1a54e5febf5d20b6aa488f3e3c917e6a96ce6461f609ec7e0a1fd8950380922e46c3654fa7542436603f833462da",
]
for i in 0 ..< knownSeckeys.len:
  var
    sk{.noinit.}: SecretKey
    pk{.noinit.}: PublicKey
    proof{.noinit.}: ProofOfPossession
  doAssert sk.fromHex(knownSeckeys[i])
  doAssert pk.fromHex(knownPubkeys[i])
  doAssert proof.fromHex(knownProofs[i])

  var pk2{.noinit.}: PublicKey
  doAssert pk2.publicFromSecret(sk)
  doAssert pk2 == pk

  let proof2 = sk.popProve(pk)
  let proof3 = sk.popProve
  doAssert proof3 == proof2
  doAssert proof2 == proof
  doAssert pk.popVerify(proof)

  var wrongPk{.noinit.}: PublicKey
  doAssert wrongPk.fromHex(knownPubkeys[(i + 1) mod knownPubkeys.len])
  doAssert not wrongPk.popVerify(proof)

template withProof(pk: PublicKey, body: untyped): untyped =
  block:
    let i = knownPubkeys.find(pk.toHex())
    doAssert i > -1, block: "\nProof for pubkey not known: " & pk.toHex()
    var proof{.inject, noinit.}, wrongProof{.inject, noinit.}: ProofOfPossession
    doAssert proof.fromHex(knownProofs[i])
    doAssert wrongProof.fromHex(knownProofs[(i + 1) mod knownProofs.len])
    body

template withProofs(pks: openArray[PublicKey], body: untyped): untyped =
  block:
    var proofs{.inject.}, wrongProofs{.inject.}: seq[ProofOfPossession]
    for pk in pks:
      let i = knownPubkeys.find(pk.toHex())
      doAssert i > -1, block: "\nProof for pubkey not known: " & pk.toHex()
      var proof, wrongProof: ProofOfPossession
      doAssert proof.fromHex(knownProofs[i])
      doAssert wrongProof.fromHex(knownProofs[(i + 1) mod knownProofs.len])
      proofs.add proof
      wrongProofs.add wrongProof
    body

template testGen*(name, testJson, body: untyped): untyped =
  ## Generates a test proc
  ## with identifier "test_name"
  ## The test file is available as JsonNode under the
  ## the variable passed as `testJson`
  proc `test _ name`() =
    var count = 0 # Need to fail if walkDir doesn't return anything
    var skipped = 0
    for dir, file{.inject.} in walkTests(astToStr(name), skipped):
      echo "       ", astToStr(name), " test: ", file
      let testJson = parseTest(dir / file)

      body

      inc count

    doAssert count > 0, "Empty or inexisting test folder: " & astToStr(name)
    if skipped > 0:
      echo "[Warning]: ", skipped, " tests skipped."

proc getFrom(T: typedesc, test: JsonNode, inout: static InOut): tuple[val: T, ok: bool] =
  when inout == Output:
    when T is bool:
      result = (test["output"].getBool(), true)
    else:
      result.ok = result.val.fromHex(test["output"].getStr())
      # if not result.ok: # We might read an empty string for N/A pubkeys
      #   echo "Couldn't parse output " & $T & ": " & test["output"].getStr()
  else:
    when T is seq[Signature]:
      for sigHex in test["input"]:
        result.val.setLen(result.val.len + 1)
        doAssert result.val[^1].fromHex(sigHex.getStr()),
          "Couldn't parse input Signature: " & sigHex.getStr()
      result.ok = true
    else:
      {.error: "Unreachable".}

proc getFrom(T: typedesc, test: JsonNode, inout: static InOut, name: string): tuple[val: T, ok: bool] =
  when inout == Output:
    {.error: "Unreachable".}
  else:
    when T is seq[byte]:
      result = (test["input"][name].getStr().hexToSeqByte(), true)
    else:
      result.ok = result.val.fromHex(test["input"][name].getStr())
      # if not result.ok:
      #   echo "Couldn't parse input '" & name & "' (" & $T &
      #     "): " & test["input"][name].getStr()

proc aggFrom(T: typedesc, test: JsonNode, name: string): tuple[val: T, ok: bool] =
  when T is seq[(PublicKey, seq[byte])]:
    doAssert name == "pubkeys/messages", "misconfiguration"
    for pubkey in test["input"]["pubkeys"]:
      result.val.setLen(result.val.len + 1)
      let ok = result.val[^1][0].fromHex(pubkey.getStr())
      if not ok:
        # echo "Couldn't parse input PublicKey: " & pubkey.getStr()
        result.ok = false
        return

    var i = 0
    for message in test["input"]["messages"]:
      result.val[i][1] = message.getStr().hexToSeqByte()
      inc i
    result.ok = true
  elif T is seq[PublicKey]:
    for pubKeyHex in test["input"][name]:
      result.val.setLen(result.val.len + 1)
      let ok = result.val[^1].fromHex(pubKeyHex.getStr())
      if not ok:
        # echo "Couldn't parse input PublicKey: " & pubKeyHex.getStr()
        result.ok = false
        return
    result.ok = true
  elif T is seq[Signature]:
    for sigHex in test["input"][name]:
      result.val.setLen(result.val.len + 1)
      let ok = result.val[^1].fromHex(sigHex.getStr())
      if not ok:
        # echo "Couldn't parse input Signature: " & sigHex.getStr()
        result.ok = false
        return
    result.ok = true
  elif T is seq[seq[byte]]:
    for message in test["input"][name]:
      result.val.setLen(result.val.len + 1)
      result.val[^1] = message.getStr().hexToSeqByte()
    result.ok = true
  else:
    {.error: "Unreachable".}

testGen(sign, test):
  let
    privKey = SecretKey.getFrom(test, Input, "privkey")
    message = seq[byte].getFrom(test, Input, "message")

    expectedSig = Signature.getFrom(test, Output)

  doAssert privKey.ok == expectedSig.ok
  if not privKey.ok or not expectedSig.ok:
    echo ("")
  else:

    let libSig = privKey.val.sign(message.val)

    doAssert libSig == expectedSig.val, block:
      "\nSignature differs from expected \n" &
      "   computed: " & libSig.toHex() & "\n" &
      "   expected: " & expectedSig.val.toHex()

testGen(verify, test):
  let
    expected = bool.getFrom(test, Output)
    pubKey = PublicKey.getFrom(test, Input, "pubkey")
    message = seq[byte].getFrom(test, Input, "message")
    signature = Signature.getFrom(test, Input, "signature")

  if not pubKey.ok:
    # Infinity pubkey and infinity signature
    doAssert not expected.val

  else:

    let libValid = pubKey.val.verify(message.val, signature.val)

    doAssert libValid == expected.val, block:
      "\nVerification differs from expected \n" &
      "   verified? " & $libValid & "\n" &
      "   expected: " & $expected.val

    if file.startsWith("verifycase_one_privkey"):
      # Skip proof-of-possession test when
      # the secret key is 0x1
      return

    withProof(pubKey.val):
      let libValid = pubKey.val.verify(proof, message.val, signature.val)

      doAssert libValid == expected.val, block:
        "\nVerification with proof-of-possession differs from expected \n" &
        "   verified? " & $libValid & "\n" &
        "   expected: " & $expected.val

      doAssert not pubKey.val.verify(wrongProof, message.val, signature.val), block:
        "\nVerification with wrong proof-of-possession succeeded"

testGen(aggregate, test):
  let sigs = seq[Signature].getFrom(test, Input)
  let expectedAgg = Signature.getFrom(test, Output)

  var libAggSig {.noinit.}: Signature
  let ok = libAggSig.aggregateAll(sigs.val)
  if not ok:
    doAssert not expectedAgg.ok
    doAssert sigs.val.len == 0

  else:

    doAssert libAggSig == expectedAgg.val, block:
      "\nSignature aggregation differs from expected \n" &
      "   computed: " & libAggSig.toHex() & "\n" &
      "   expected: " & expectedAgg.val.toHex()

testGen(fast_aggregate_verify, test):
  let
    expected = bool.getFrom(test, Output)
    pubKeys = seq[PublicKey].aggFrom(test, "pubkeys")
    message = seq[byte].getFrom(test, Input, "message")
    signature = Signature.getFrom(test, Input, "signature")

  if not pubKeys.ok:
    # Infinity pubkey in the mix
    doAssert not expected.val

  else:

    let libValid = pubKeys.val.fastAggregateVerify(message.val, signature.val)

    doAssert libValid == expected.val, block:
      "\nFast Aggregate Verification differs from expected \n" &
      "   verified? " & $libValid & "\n" &
      "   expected: " & $expected.val

    withProofs(pubKeys.val):
      let libValid = pubKeys.val.fastAggregateVerify(proofs, message.val, signature.val)

      doAssert libValid == expected.val, block:
        "\nFast Aggregate Verification with proof-of-possession differs from expected \n" &
        "   verified? " & $libValid & "\n" &
        "   expected: " & $expected.val

      doAssert not pubKeys.val.fastAggregateVerify(wrongProofs, message.val, signature.val), block:
        "\nFast Aggregate Verification with wrong proof-of-possession succeeded"

testGen(aggregate_verify, test):
  let
    expected = bool.getFrom(test, Output)
    # We test both the SoA and AoS API
    pubkey_msg_pairs = seq[(PublicKey, seq[byte])].aggFrom(test, "pubkeys/messages")
    pubkeys = seq[PublicKey].aggFrom(test, "pubkeys")
    msgs = seq[seq[byte]].aggFrom(test, "messages")
    signature = Signature.getFrom(test, Input, "signature")

  let libAoSValid = aggregateVerify(pubkey_msg_pairs.val, signature.val)
  let libSoAValid = aggregateVerify(pubkeys.val, msgs.val, signature.val)

  if not pubkeys.ok:
    # Infinity pubkey in the mix
    doAssert not pubkey_msg_pairs.ok
    doAssert not expected.val

  else:

    doAssert libAoSValid == expected.val, block:
      "\nAggregate Verification differs from expected \n" &
      "   verified? " & $libAoSValid & "\n" &
      "   expected: " & $expected.val

    doAssert libSoAValid == expected.val, block:
      "\nAggregate Verification differs from expected \n" &
      "   verified? " & $libSoAValid & "\n" &
      "   expected: " & $expected.val

    withProofs(pubkeys.val):
      let libValid = pubkeys.val.aggregateVerify(proofs, msgs.val, signature.val)

      doAssert libValid == expected.val, block:
        "\nAggregate Verification with proof-of-possession differs from expected \n" &
        "   verified? " & $libValid & "\n" &
        "   expected: " & $expected.val

      doAssert not pubkeys.val.aggregateVerify(wrongProofs, msgs.val, signature.val), block:
        "\nAggregate Verification with wrong proof-of-possession succeeded"

testGen(deserialization_G1, test):
  var
    pubkey{.noinit.}: PublicKey

  let
    expected = bool.getFrom(test, Output)
    deserialized = pubkey.fromHex(test["input"]["pubkey"].getStr())

  doAssert deserialized == expected.val, block:
    "\nDeserialization differs from expected \n" &
    "   deserializable? " & $deserialized & "\n" &
    "   expected: " & $expected.val

testGen(deserialization_G2, test):
  var
    sig{.noinit.}: Signature

  let
    expected = bool.getFrom(test, Output)
    deserialized = sig.fromHex(test["input"]["signature"].getStr())

  doAssert deserialized == expected.val, block:
    "\nDeserialization differs from expected \n" &
    "   deserializable? " & $deserialized & "\n" &
    "   expected: " & $expected.val

when BLS_BACKEND == BLST and compileOption("threads"):
  testGen(batch_verify, test):
    # Only valid for BLST and with --threads:on

    let
      expected = bool.getFrom(test, Output)
      # Spec uses pubkeys plural but test vectors are singular ...
      pubkeys = seq[PublicKey].aggFrom(test, "pubkeys")
      messages = seq[seq[byte]].aggFrom(test, "messages")
      signatures = seq[Signature].aggFrom(test, "signatures")

    var tp = Taskpool.new(numThreads = 4)
    var cache: BatchedBLSVerifierCache
    var batch: seq[SignatureSet]


    proc hash[T: byte|char](message: openArray[T]): array[32, byte] {.noinit.} =
      result.bls_sha256_digest(message)

    proc asArray[T: byte|char](message: openArray[T]): array[32, byte] {.noinit.}=
      result[0 ..< 32] = message

    let fakeRandomBytes = hash"Mr F was here"

    # Deserialization is OK
    doAssert pubkeys.ok
    doAssert messages.ok
    doAssert signatures.ok
    doAssert pubkeys.val.len == messages.val.len
    doAssert pubkeys.val.len == signatures.val.len

    for i in 0 ..< pubkeys.val.len:
      batch.add((
        pubkeys.val[i],
        messages.val[i].asArray(),
        signatures.val[i]
      ))

    let batchValid = tp.batchVerify(cache, batch, fakeRandomBytes)
    let batchValid2 = tp.batchVerify(batch, fakeRandomBytes)

    doAssert batchValid == batchValid2
    doAssert batchValid == expected.val, block:
      "\nBatch Verification differs from expected \n" &
      "   verified? " & $batchValid & "\n" &
      "   expected: " & $expected.val

    tp.shutdown()

suite "ETH 2.0 " & BLS_ETH2_SPEC & " test vectors - " & $BLS_BACKEND:
  test "[" & BLS_ETH2_SPEC & "] sign(SecretKey, message) -> Signature":
    test_sign()
  test "[" & BLS_ETH2_SPEC & "] verify(PublicKey, message, Signature) -> bool":
    test_verify()
  test "[" & BLS_ETH2_SPEC & "] aggregate(openArray[Signature]) -> Signature":
    test_aggregate()
  test "[" & BLS_ETH2_SPEC & "] fastAggregateVerify(openArray[PublicKey], message, Signature) -> bool":
    test_fast_aggregate_verify()
  test "[" & BLS_ETH2_SPEC & "] AggregateVerify(openArray[PublicKey, message], Signature) -> bool":
    test_aggregate_verify()
  test "[" & BLS_ETH2_SPEC & "] Deserialization_G1(PublicKey) -> bool":
    test_deserialization_G1()
  test "[" & BLS_ETH2_SPEC & "] Deserialization_G2(Signature) -> bool":
    test_deserialization_G2()

  when BLS_BACKEND == BLST and compileOption("threads"):
    test "[" & BLS_ETH2_SPEC & "] BatchVerify(openArray[(PublicKey, message, Signatures)]) -> bool":
      test_batch_verify()
  else:
    echo "  [SKIP] [v1.0.0] BatchVerify(openArray[(PublicKey, message, Signatures)]) -> bool"
    echo "    Not using BLST backend or --threads:on"

  echo "  [SKIP] [v1.0.0] HashToG2 tests"
  # We skip the hashToG2 tests since they are lower-level than the nim-blscurve library.
  # They are also implicitly tested by sign/verify.
  # For our own implementation using Miracl, tests are in blscurve/miracl/hash_to_curve.nim
