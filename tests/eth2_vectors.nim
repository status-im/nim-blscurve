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

proc getFrom(T: typedesc, test: JsonNode, inout: static InOut): T =
  when inout == Output:
    when T is bool:
      result = test["output"].getBool()
    else:
      let maybeParsed = result.fromHex(test["output"].getStr())
      if not maybeParsed: # We might read an empty string for N/A pubkeys
        doAssert test["output"].getStr() == "",
          "Couldn't parse output " & $T & ": " & test["output"].getStr()
  else:
    when T is seq[Signature]:
      for sigHex in test["input"]:
        result.setLen(result.len + 1)
        doAssert result[^1].fromHex(sigHex.getStr()),
          "Couldn't parse input Signature: " & sigHex.getStr()
    else:
      {.error: "Unreachable".}

proc getFrom(T: typedesc, test: JsonNode, inout: static InOut, name: string): T =
  when inout == Output:
    {.error: "Unreachable".}
  else:
    when T is seq[byte]:
      result = test["input"][name].getStr().hexToSeqByte()
    elif T is seq[PublicKey]:
      for pubKeyHex in test["input"][name]:
        result.setLen(result.len + 1)
        doAssert result[^1].fromHex(pubKeyHex.getStr()),
          "Couldn't parse input PublicKey: " & pubKeyHex.getStr()
    else:
      doAssert result.fromHex(test["input"][name].getStr()),
          "Couldn't parse input '" & name & "' (" & $T &
          "): " & test["input"][name].getStr()

when BLS_ETH2_SPEC == "v0.12.x":
  proc aggFrom(T: typedesc, test: JsonNode): T =
    when T is seq[(PublicKey, seq[byte])]:
      for pubkey in test["input"]["pubkeys"]:
        result.setLen(result.len + 1)
        doAssert result[^1][0].fromHex(pubkey.getStr()),
            "Couldn't parse input PublicKey: " & pubkey.getStr()
      var i = 0
      for message in test["input"]["messages"]:
        result[i][1] = message.getStr().hexToSeqByte()
        inc i
    elif T is seq[PublicKey]:
      for pubkey in test["input"]["pubkeys"]:
        result.setLen(result.len + 1)
        doAssert result[^1].fromHex(pubkey.getStr()),
            "Couldn't parse input PublicKey: " & pubkey.getStr()
    elif T is seq[seq[byte]]:
      for message in test["input"]["messages"]:
        result.setLen(result.len + 1)
        result[^1] = message.getStr().hexToSeqByte()
    else:
      {.error: "Unreachable".}
else:
  proc aggFrom(T: typedesc, test: JsonNode): T =
    when T is seq[(PublicKey, seq[byte])]:
      for pair in test["input"]["pairs"]:
        result.setLen(result.len + 1)
        doAssert result[^1][0].fromHex(pair["pubkey"].getStr()),
            "Couldn't parse input PublicKey: " & pair["pubkey"].getStr()
        result[^1][1] = pair["message"].getStr().hexToSeqByte()
    elif T is seq[PublicKey]:
      for pair in test["input"]["pairs"]:
        result.setLen(result.len + 1)
        doAssert result[^1].fromHex(pair["pubkey"].getStr()),
            "Couldn't parse input PublicKey: " & pair["pubkey"].getStr()
    elif T is seq[seq[byte]]:
      for pair in test["input"]["pairs"]:
        result.setLen(result.len + 1)
        result[^1] = pair["message"].getStr().hexToSeqByte()
    else:
      {.error: "Unreachable".}

testGen(sign, test):
  let
    privKey = SecretKey.getFrom(test, Input, "privkey")
    message = seq[byte].getFrom(test, Input, "message")

    expectedSig = Signature.getFrom(test, Output)

  let libSig = privKey.sign(message)

  doAssert libSig == expectedSig, block:
    "\nSignature differs from expected \n" &
    "   computed: " & libSig.toHex() & "\n" &
    "   expected: " & expectedSig.toHex()

testGen(verify, test):
  let expected = bool.getFrom(test, Output)
  var
    pubkey: PublicKey
    message: seq[byte]
    signature: Signature
  try:
    pubKey = PublicKey.getFrom(test, Input, "pubkey")
    message = seq[byte].getFrom(test, Input, "message")
    signature = Signature.getFrom(test, Input, "signature")
  except:
    let emsg = getCurrentExceptionMsg()
    if expected:
      doAssert false, "Verification was not supposed to fail, but one of the inputs was invalid." & emsg
    else:
      echo "[INFO] Expected verification failure at parsing stage: " & emsg

  let libValid = pubKey.verify(message, signature)

  doAssert libValid == expected, block:
    "\nVerification differs from expected \n" &
    "   computed: " & $libValid & "\n" &
    "   expected: " & $expected

testGen(aggregate, test):
  let sigs = seq[Signature].getFrom(test, Input)
  let expectedAgg = Signature.getFrom(test, Output)

  # TODO - at which level should we catch the empty signatures?
  if sigs.len == 0:
    echo "       ⚠⚠⚠ Skipping empty aggregation, handled at the client level"
    return

  let libAggSig = aggregate(sigs)

  doAssert libAggSig == expectedAgg, block:
    "\nSignature aggregation differs from expected \n" &
    "   computed: " & libAggSig.toHex() & "\n" &
    "   expected: " & expectedAgg.toHex()

testGen(fast_aggregate_verify, test):
  let expected = bool.getFrom(test, Output)
  var
    pubkeys: seq[PublicKey]
    message: seq[byte]
    signature: Signature
  try:
    pubKeys = seq[PublicKey].getFrom(test, Input, "pubkeys")
    message = seq[byte].getFrom(test, Input, "message")
    signature = Signature.getFrom(test, Input, "signature")
  except:
    let emsg = getCurrentExceptionMsg()
    if expected:
      doAssert false, "Verification was not supposed to fail, but one of the inputs was invalid." & emsg
    else:
      echo "[INFO] Expected verification failure at parsing stage: " & emsg

  let libValid = pubKeys.fastAggregateVerify(message, signature)

  doAssert libValid == expected, block:
    "\nFast Aggregate Verification differs from expected \n" &
    "   computed: " & $libValid & "\n" &
    "   expected: " & $expected

testGen(aggregate_verify, test):
  let expected = bool.getFrom(test, Output)
  var
    # We test both the SoA and AoS API
    pubkey_msg_pairs: seq[(PublicKey, seq[byte])]
    pubkeys: seq[PublicKey]
    msgs: seq[seq[byte]]
    signature: Signature
  try:
    pubkey_msg_pairs = seq[(PublicKey, seq[byte])].aggFrom(test)
    pubkeys = seq[PublicKey].aggFrom(test)
    msgs = seq[seq[byte]].aggFrom(test)
    signature = Signature.getFrom(test, Input, "signature")
  except:
    let emsg = getCurrentExceptionMsg()
    if expected:
      doAssert false, "Verification was not supposed to fail, but one of the inputs was invalid." & emsg
    else:
      echo "[INFO] Expected verification failure at parsing stage: " & emsg

  let libAoSValid = aggregateVerify(pubkey_msg_pairs, signature)
  let libSoAValid = aggregateVerify(pubkeys, msgs, signature)

  doAssert libAoSValid == expected, block:
    "\nAggregate Verification differs from expected \n" &
    "   computed: " & $libAoSValid & "\n" &
    "   expected: " & $expected

  doAssert libSoAValid == expected, block:
    "\nAggregate Verification differs from expected \n" &
    "   computed: " & $libSoAValid & "\n" &
    "   expected: " & $expected

suite "ETH 2.0 " & BLS_ETH2_SPEC & " test vectors":
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
