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
  json, strutils, os, unittest,
  # Status libraries
  stew/byteutils,
  # Public API
  ../blscurve, ../blscurve/bls_sig_min_pubkey,
  # Test helpers
  ./test_locator

type InOut = enum
  Input
  Output

# Eth2 vectors do not include proof-of-possession data.
# By adding proof data here, we can leverage the existing tests to also cover proof-of-possession functionality.
# See https://github.com/ethereum/eth2.0-specs/blob/dev/tests/generators/bls/main.py#L45-L51
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
    sk{.noInit.}: SecretKey
    pk{.noInit.}: PublicKey
    proof{.noInit.}: ProofOfPossession
  doAssert sk.fromHex(knownSeckeys[i])
  doAssert pk.fromHex(knownPubkeys[i])
  doAssert proof.fromHex(knownProofs[i])

  var pk2{.noInit.}: PublicKey
  doAssert pk2.publicFromSecret(sk)
  doAssert pk2 == pk

  let proof2 = sk.popProve(pk)
  let proof3 = sk.popProve
  doAssert proof3 == proof2
  doAssert proof2 == proof
  doAssert pk.popVerify(proof)

  var wrongPk{.noInit.}: PublicKey
  doAssert wrongPk.fromHex(knownPubkeys[(i + 1) mod knownPubkeys.len])
  doAssert not wrongPk.popVerify(proof)

template withProof(pk: PublicKey, body: untyped): untyped =
  block:
    let i = knownPubkeys.find(pk.toHex())
    doAssert i > -1, block: "\nProof for pubkey not known: " & pk.toHex()
    var proof{.inject, noInit.}, wrongProof{.inject, noInit.}: ProofOfPossession
    doAssert proof.fromHex(knownProofs[i])
    doAssert wrongProof.fromHex(knownProofs[(i + 1) mod knownProofs.len])
    body
    
template withProofs(pks: openarray[PublicKey], body: untyped): untyped =
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
  ## The test file is availaible as JsonNode under the
  ## the variable passed as `testJson`
  proc `test _ name`() =
    var count = 0 # Need to fail if walkDir doesn't return anything
    var skipped = 0
    for dir, file in walkTests(astToStr(name), skipped):
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
    elif T is seq[PublicKey]:
      for pubKeyHex in test["input"][name]:
        result.val.setLen(result.val.len + 1)
        let ok = result.val[^1].fromHex(pubKeyHex.getStr())
        if not ok:
          # echo "Couldn't parse input PublicKey: " & pubKeyHex.getStr()
          result.ok = false
          return
      result.ok = true
    else:
      result.ok = result.val.fromHex(test["input"][name].getStr())
      # if not result.ok:
      #   echo "Couldn't parse input '" & name & "' (" & $T &
      #     "): " & test["input"][name].getStr()

proc aggFrom(T: typedesc, test: JsonNode): tuple[val: T, ok: bool] =
  when T is seq[(PublicKey, seq[byte])]:
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
    for pubkey in test["input"]["pubkeys"]:
      result.val.setLen(result.val.len + 1)
      let ok = result.val[^1].fromHex(pubkey.getStr())
      if not ok:
        # echo "Couldn't parse input PublicKey: " & pubkey.getStr()
        result.ok = false
        return
    result.ok = true
  elif T is seq[seq[byte]]:
    for message in test["input"]["messages"]:
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

  doAssert privkey.ok == expectedSig.ok
  if not privkey.ok or not expectedSig.ok:
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

  if not pubkey.ok:
    # Infinity pubkey and infinity signature
    doAssert not expected.val
  
  else:

    let libValid = pubKey.val.verify(message.val, signature.val)

    doAssert libValid == expected.val, block:
      "\nVerification differs from expected \n" &
      "   computed: " & $libValid & "\n" &
      "   expected: " & $expected.val

    withProof(pubKey.val):
      let libValid = pubKey.val.verify(proof, message.val, signature.val)

      doAssert libValid == expected.val, block:
        "\nVerification with proof-of-possession differs from expected \n" &
        "   computed: " & $libValid & "\n" &
        "   expected: " & $expected.val

      doAssert not pubKey.val.verify(wrongProof, message.val, signature.val), block:
        "\nVerification with wrong proof-of-possession succeeded"

testGen(aggregate, test):
  let sigs = seq[Signature].getFrom(test, Input)
  let expectedAgg = Signature.getFrom(test, Output)

  var libAggSig {.noInit.}: Signature
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
    pubKeys = seq[PublicKey].getFrom(test, Input, "pubkeys")
    message = seq[byte].getFrom(test, Input, "message")
    signature = Signature.getFrom(test, Input, "signature")

  if not pubkeys.ok:
    # Infinity pubkey in the mix
    doAssert not expected.val

  else:

    let libValid = pubKeys.val.fastAggregateVerify(message.val, signature.val)

    doAssert libValid == expected.val, block:
      "\nFast Aggregate Verification differs from expected \n" &
      "   computed: " & $libValid & "\n" &
      "   expected: " & $expected.val
      
    withProofs(pubKeys.val):
      let libValid = pubKeys.val.fastAggregateVerify(proofs, message.val, signature.val)

      doAssert libValid == expected.val, block:
        "\nFast Aggregate Verification with proof-of-possession differs from expected \n" &
        "   computed: " & $libValid & "\n" &
        "   expected: " & $expected.val

      doAssert not pubKeys.val.fastAggregateVerify(wrongProofs, message.val, signature.val), block:
        "\nFast Aggregate Verification with wrong proof-of-possession succeeded"

testGen(aggregate_verify, test):
  let
    expected = bool.getFrom(test, Output)
    # We test both the SoA and AoS API
    pubkey_msg_pairs = seq[(PublicKey, seq[byte])].aggFrom(test)
    pubkeys = seq[PublicKey].aggFrom(test)
    msgs = seq[seq[byte]].aggFrom(test)
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
      "   computed: " & $libAoSValid & "\n" &
      "   expected: " & $expected.val

    doAssert libSoAValid == expected.val, block:
      "\nAggregate Verification differs from expected \n" &
      "   computed: " & $libSoAValid & "\n" &
      "   expected: " & $expected.val

    withProofs(pubkeys.val):
      let libValid = pubkeys.val.aggregateVerify(proofs, msgs.val, signature.val)

      doAssert libValid == expected.val, block:
        "\nAggregate Verification with proof-of-possession differs from expected \n" &
        "   computed: " & $libValid & "\n" &
        "   expected: " & $expected.val

      doAssert not pubkeys.val.aggregateVerify(wrongProofs, msgs.val, signature.val), block:
        "\nAggregate Verification with wrong proof-of-possession succeeded"

suite "ETH 2.0 " & BLS_ETH2_SPEC & " test vectors - " & $BLS_BACKEND:
  test "[" & BLS_ETH2_SPEC & "] sign(SecretKey, message) -> Signature":
    test_sign()
  test "[" & BLS_ETH2_SPEC & "] verify(PublicKey, message, Signature) -> bool":
    test_verify()
  test "[" & BLS_ETH2_SPEC & "] aggregate(openarray[Signature]) -> Signature":
    test_aggregate()
  test "[" & BLS_ETH2_SPEC & "] fastAggregateVerify(openarray[PublicKey], message, Signature) -> bool":
    test_fast_aggregate_verify()
  test "[" & BLS_ETH2_SPEC & "] AggregateVerify(openarray[PublicKey, message], Signature) -> bool":
    test_aggregate_verify()
