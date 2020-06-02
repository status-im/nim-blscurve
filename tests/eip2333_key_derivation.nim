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
  var tmp: array[48, byte]
  let ok = tmp.serialize(sk)
  doAssert ok
  var asBytes: array[32, byte]
  asBytes[0 .. 31] = tmp.toOpenArray(48-32, 48-1)

  let asInt = readUintBE[256](asBytes)
  result = toString(asInt, radix = 10)

proc test0 =
  let seed = hexToSeqByte"0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
  let expectedMaster = "12513733877922233913083619867448865075222526338446857121953625441395088009793"
  let child_index = 0'u32
  let expectedChild = "7419543105316279183937430842449358701327973165530407166294956473095303972104"

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
  let expectedMaster = "46029459550803682895343812821003080589696405386150182061394330539196052371668"
  let child_index = 3141592653'u32
  let expectedChild = "43469287647733616183478983885105537266268532274998688773496918571876759327260"

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
  let expectedMaster = "45379166311535261329029945990467475187325618028073620882733843918126031931161"
  let child_index = 4294967295'u32
  let expectedChild = "46475244006136701976831062271444482037125148379128114617927607151318277762946"

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
  let expectedMaster = "31740500954810567003972734830331791822878290325762596213711963944729383643688"
  let child_index = 42'u32
  let expectedChild = "51041472511529980987749393477251359993058329222191894694692317000136653813011"

  var master: SecretKey
  let ok0 = master.derive_master_secretKey(seed)
  doAssert ok0

  doAssert master.toDecimal == expectedMaster

  var child: SecretKey
  let ok1 = child.derive_child_secretKey(master, child_index)
  doAssert ok1

  doAssert child.toDecimal == expectedChild

suite "Key Derivation (EIP-2333)":
  test "Test 0":
    test0()
  test "Test 1":
    test1()
  test "Test 2":
    test2()
  test "Test 3":
    test3()

# Reference: https://eips.ethereum.org/EIPS/eip-2333
#
# ### Test Case 0
#
# ```text
# seed = 0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
# master_SK = 12513733877922233913083619867448865075222526338446857121953625441395088009793
# child_index = 0
# child_SK = 7419543105316279183937430842449358701327973165530407166294956473095303972104
# ```
#
# ### Test Case 1
#
# ```text
# seed = 0x3141592653589793238462643383279502884197169399375105820974944592
# master_SK = 46029459550803682895343812821003080589696405386150182061394330539196052371668
# child_index = 3141592653
# child_SK = 43469287647733616183478983885105537266268532274998688773496918571876759327260
# ```
#
# ### Test Case 2
#
# ```text
# seed = 0x0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00
# master_SK = 45379166311535261329029945990467475187325618028073620882733843918126031931161
# child_index = 4294967295
# child_SK = 46475244006136701976831062271444482037125148379128114617927607151318277762946
# ```
#
# ### Test Case 3
#
# ```text
# seed = 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3
# master_SK = 31740500954810567003972734830331791822878290325762596213711963944729383643688
# child_index = 42
# child_SK = 51041472511529980987749393477251359993058329222191894694692317000136653813011
# ```
