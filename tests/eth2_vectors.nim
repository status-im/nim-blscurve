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

template testGen(name, testJson, body: untyped): untyped =
  ## Generates a test proc
  ## with identifier "test_name"
  ## The test file is availaible as JsonNode under the
  ## the variable passed as `testJson`
  proc `test _ name`() =
    var count = 0 # Need to fail if walkDir doesn't return anything
    const testDir = ETH2_DIR / astToStr(name)
    for file in walkDirRec(testDir, relative = true):
      echo "       ", astToStr(name), " test: ", file
      let testJson = parseTest(testDir / file)

      body

      inc count

    doAssert count > 0, "Empty or inexisting test folder: " & astToStr(name)

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
      result = hexToSeqByte(test["input"][name].getStr)
    else:
      doAssert result.fromHex(test["input"][name].getStr()),
          "Couldn't parse input '" & name & "' (" & $T &
          "): " & test["input"][name].getStr()

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

suite "ETH 2.0 v0.10.1 test vectors":
  test "sign(SecretKey, message) -> Signature":
    test_sign()
  test "verify(PublicKey, message, Signature) -> bool":
    test_verify()
  test "aggregate(openarray[Signature]) -> Signature":
    test_aggregate()
