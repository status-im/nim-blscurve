# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Test implementation of Cipher Suite BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_POP_
# against Eth2 v0.10.1 vectors

import
  # Standard library
  json, strutils, os, streams, unittest,
  # Third party
  yaml,
  # Status libraries
  stew/byteutils,
  # Public API
  ../blscurve

const ETH2_DIR = currentSourcePath.rsplit(DirSep, 1)[0] / "eth2.0_v0.10.1_vectors"

doAssert BLS_USE_IETF_API, "Testing against the IETF standard requires using that standard."

proc parseTest(file: string): JsonNode =
  var yamlStream = openFileStream(file)
  defer: yamlStream.close()
  result = yamlStream.loadToJson()[0]

const SkippedTests = [
  "small"/"fast_aggregate_verify_e6922a0d196d9869"/"data.yaml", # Buggy upstream vector: https://github.com/ethereum/eth2.0-specs/issues/1618
  "small"/"fast_aggregate_verify_62bca7cd61880e26"/"data.yaml",
  "small"/"fast_aggregate_verify_3b2b0141e95125f0"/"data.yaml",
]

template testGen(name, testJson, body: untyped): untyped =
  ## Generates a test proc
  ## with identifier "test_name"
  ## The test file is availaible as JsonNode under the
  ## the variable passed as `testJson`
  proc `test _ name`() =
    var count = 0 # Need to fail if walkDir doesn't return anything
    var skipped = 0
    const testDir = ETH2_DIR / astToStr(name)
    for file in walkDirRec(testDir, relative = true):
      if file in SkippedTests:
        echo "[WARNING] Skipping - ", file
        inc skipped
        continue
      echo "       ", astToStr(name), " test: ", file
      let testJson = parseTest(testDir / file)

      body

      inc count

    doAssert count > 0, "Empty or inexisting test folder: " & astToStr(name)
    if skipped > 0:
      echo "[Warning]: ", skipped, " tests skipped."

type InOut = enum
  Input
  Output

proc getFrom(T: typedesc, test: JsonNode, inout: static InOut): T =
  when inout == Output:
    when T is bool:
      result = test["output"].getBool()
    else:
      doAssert result.fromHex(test["output"].getStr()),
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

suite "ETH 2.0 v0.10.1 test vectors":
  test "sign(SecretKey, message) -> Signature":
    test_sign()
  test "verify(PublicKey, message, Signature) -> bool":
    test_verify()
  test "aggregate(openarray[Signature]) -> Signature":
    test_aggregate()
  test "fastAggregateVerify(openarray[PublicKey], message, Signature) -> bool":
    test_fast_aggregate_verify()
  test "AggregateVerify(openarray[PublicKey, message], Signature) -> bool":
    test_aggregate_verify()
