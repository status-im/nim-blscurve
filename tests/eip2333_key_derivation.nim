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
  unittest,
  # Status libraries
  stew/byteutils, stint,
  # Public API
  ../blscurve,
  # Test helpers
  ./test_locator

proc toDecimal(sk: SecretKey): string =
  # The spec does not use hex but decimal ...
  var asBytes: array[32, byte]
  when BLS_BACKEND == "miracl":
    var tmp: array[48, byte]
    let ok = tmp.serialize(sk)
    doAssert ok
    asBytes[0 .. 31] = tmp.toOpenArray(48-32, 48-1)
  else:
    let ok = asBytes.serialize(sk)

  let asInt = readUintBE[256](asBytes)
  result = toString(asInt, radix = 10)

proc test0 =
  let seed = hexToSeqByte"0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  let expectedMaster = "5399117110774477986698372024995405256382522670366369834617409486544348441851"
  let child_index = 0'u32
  let expectedChild = "11812940737387919040225825939013910852517748782307378293770044673328955938106"

  var master: SecretKey
  let ok0 = master.derive_master_secretKey(seed)
  doAssert ok0

  doAssert master.toDecimal == expectedMaster

  var child: SecretKey
  let ok1 = child.derive_child_secretKey(master, child_index)
  doAssert ok1

  doAssert child.toDecimal == expectedChild

proc test1 =
  let seed = hexToSeqByte"0x3141592653589793238462643383279502884197169399375105820974944592"
  let expectedMaster = "36167147331491996618072159372207345412841461318189449162487002442599770291484"
  let child_index = 3141592653'u32
  let expectedChild = "41787458189896526028601807066547832426569899195138584349427756863968330588237"

  var master: SecretKey
  let ok0 = master.derive_master_secretKey(seed)
  doAssert ok0

  doAssert master.toDecimal == expectedMaster

  var child: SecretKey
  let ok1 = child.derive_child_secretKey(master, child_index)
  doAssert ok1

  doAssert child.toDecimal == expectedChild

proc test2 =
  let seed = hexToSeqByte"0x0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00"
  let expectedMaster = "13904094584487173309420026178174172335998687531503061311232927109397516192843"
  let child_index = 4294967295'u32
  let expectedChild = "12482522899285304316694838079579801944734479969002030150864436005368716366140"

  var master: SecretKey
  let ok0 = master.derive_master_secretKey(seed)
  doAssert ok0

  doAssert master.toDecimal == expectedMaster

  var child: SecretKey
  let ok1 = child.derive_child_secretKey(master, child_index)
  doAssert ok1

  doAssert child.toDecimal == expectedChild

proc test3 =
  let seed = hexToSeqByte"0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
  let expectedMaster = "44010626067374404458092393860968061149521094673473131545188652121635313364506"
  let child_index = 42'u32
  let expectedChild = "4011524214304750350566588165922015929937602165683407445189263506512578573606"

  var master: SecretKey
  let ok0 = master.derive_master_secretKey(seed)
  doAssert ok0

  doAssert master.toDecimal == expectedMaster

  var child: SecretKey
  let ok1 = child.derive_child_secretKey(master, child_index)
  doAssert ok1

  doAssert child.toDecimal == expectedChild

suite "Key Derivation (EIP-2333) - " & BLS_BACKEND:
  test "Test 0":
    test0()
  test "Test 1":
    test1()
  test "Test 2":
    test2()
  test "Test 3":
    test3()
