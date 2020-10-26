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
  ../blscurve,
  # Test helpers
  ./test_locator

type InOut = enum
  Input
  Output

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
    return

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
    return

  let libValid = pubKey.val.verify(message.val, signature.val)

  doAssert libValid == expected.val, block:
    "\nVerification differs from expected \n" &
    "   computed: " & $libValid & "\n" &
    "   expected: " & $expected.val

testGen(aggregate, test):
  let sigs = seq[Signature].getFrom(test, Input)
  let expectedAgg = Signature.getFrom(test, Output)

  var libAggSig {.noInit.}: Signature
  let ok = libAggSig.aggregateAll(sigs.val)
  if not ok:
    doAssert not expectedAgg.ok
    doAssert sigs.val.len == 0
    return

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
    return

  let libValid = pubKeys.val.fastAggregateVerify(message.val, signature.val)

  doAssert libValid == expected.val, block:
    "\nFast Aggregate Verification differs from expected \n" &
    "   computed: " & $libValid & "\n" &
    "   expected: " & $expected.val

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
    return

  doAssert libAoSValid == expected.val, block:
    "\nAggregate Verification differs from expected \n" &
    "   computed: " & $libAoSValid & "\n" &
    "   expected: " & $expected.val

  doAssert libSoAValid == expected.val, block:
    "\nAggregate Verification differs from expected \n" &
    "   computed: " & $libSoAValid & "\n" &
    "   expected: " & $expected.val

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
