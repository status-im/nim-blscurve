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

proc testSign() =
  var count = 0 # Need to fail if walkDir doesn't return anything
  const signDir = ETH2_DIR / "sign"
  for file in walkDirRec(signDir, relative = true):
    echo "       sign test: ", file
    let test = parseTest(ETH2_DIR / "sign" / file)
    var privKey: SecretKey
    doAssert privKey.fromHex(test["input"]["privkey"].getStr), "Couldn't parse the private key"
    let message = hexToSeqByte(test["input"]["message"].getStr)

    let libSig = privKey.sign(message)

    var expectedSig: Signature
    doAssert expectedSig.fromHex(test["output"].getStr), "Couldn't parse the expected signature"
    let bLibSig = cast[array[sizeof(Signature), byte]](libSig)
    let bExpectedSig = cast[array[sizeof(Signature), byte]](expectedSig)

    doAssert libSig == expectedSig, block:
      "\nSignature differs from expected \n" &
      "   computed: " & libSig.toHex() & "\n" &
      "   expected: " & expectedSig.toHex()

    inc count
  doAssert count > 0, "Empty test folder"

suite "ETH 2.0 v0.10.1 test vectors":
  test "sign(SecretKey, message) -> Signature":
    testSign()
