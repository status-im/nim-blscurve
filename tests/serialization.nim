# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import ../blscurve, std/strutils

# Infinite signatures serialization
# A signature may be initialized at an infinity point
# as a first step before aggregation. Inputs

when BLS_BACKEND == BLST:
  echo "\nZero init signatures is serialized as infinity point"
  echo "----------------------------------\n"
  proc test_zero_sig() =

    block:
      let sig = Signature()
      doAssert sig.toHex() == "c" & '0'.repeat(191)

    block:
      let sig = AggregateSignature()
      doAssert sig.toHex() == "c" & '0'.repeat(191)

  test_zero_sig()

# [Security] Harden against seemingly valid BLS signature
# https://github.com/status-im/nimbus-eth2/issues/555

echo "\nInvalid infinity point encoding"
echo "----------------------------------\n"

proc test_invalid_infinity() =
  let sigbytes = @[byte 217, 149, 255, 97, 73, 133, 236, 43, 248, 34, 30, 10, 15, 45, 82, 72, 243, 179, 53, 17, 27, 17, 248, 180, 7, 92, 200, 153, 11, 3, 111, 137, 124, 171, 29, 218, 191, 246, 148, 57, 160, 50, 232, 129, 81, 90, 72, 161, 110, 138, 243, 116, 0, 88, 125, 180, 67, 153, 194, 181, 117, 152, 166, 147, 13, 77, 15, 91, 33, 50, 140, 199, 150, 10, 15, 10, 209, 165, 38, 57, 56, 114, 175, 29, 49, 11, 11, 126, 55, 189, 170, 46, 218, 240, 189, 144]
  var sig: Signature
  let success = sig.fromBytes(sigbytes)
  doAssert not success

test_invalid_infinity()

# This test ensures that serialization roundtrips work

echo "\nserialization roundtrip"
echo "----------------------------------\n"

proc test_serialization() =
  # MSGs taken from the hash-to-curve IETF spec
  const msgs = [
    "",
    "abc",
    "abcdef0123456789",
    "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" &
      "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" &
      "qqqqqqqqqqqqqqqqqqqqqqqqq",
    "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ]

  const seckeys = [
    "00000000000000000000000000000000000000000000000000000000000003e8",
    "00000000000000000000000000000000000000000000000000000000000003e9",
    "00000000000000000000000000000000000000000000000000000000000003ea",
    "00000000000000000000000000000000000000000000000000000000000003eb",
    "00000000000000000000000000000000000000000000000000000000000003ec"
  ]

  # Pubkey serialization
  # --------------------
  for seckey in seckeys:
    var
      sk{.noinit.}: SecretKey
      pk{.noinit.}: PublicKey
      # pk_uncomp{.noinit.}: array[96, byte]
      pk_comp{.noinit.}: array[48, byte]
    let ok = sk.fromHex(seckey)
    doAssert ok
    let ok2 = pk.publicFromSecret(sk)
    doAssert ok2

    # Serialize compressed and uncompressed
    doAssert pk_comp.serialize(pk)
    # doAssert pk_uncomp.serialize(pk)

    var pk2{.noinit.}: PublicKey
    # var pk3{.noinit.}: PublicKey

    doAssert pk2.fromBytes(pk_comp)
    # doAssert pk3.fromBytes(pk_uncomp)

    doAssert pk == pk2
    # doAssert pk == pk3

  # Signature serialization
  # -----------------------
  for seckey in seckeys:
    var
      sk{.noinit.}: SecretKey
      pk{.noinit.}: PublicKey
      # pk_uncomp{.noinit.}: array[96, byte]
      pk_comp{.noinit.}: array[48, byte]
    let ok = sk.fromHex(seckey)
    doAssert ok
    let ok2 = pk.publicFromSecret(sk)
    doAssert ok2

    for msg in msgs:
      let sig = sk.sign(msg)

      var
        sig_uncomp{.noinit.}: array[192, byte]
        sig_comp{.noinit.}: array[96, byte]

      # Serialize compressed and uncompressed
      doAssert sig_comp.serialize(sig)
      # doAssert sig_uncomp.serialize(sig)

      var sig2{.noinit.}: Signature
      # var sig3{.noinit.}: Signature

      doAssert sig2.fromBytes(sig_comp)
      # doAssert sig3.fromBytes(sig_uncomp)

      doAssert sig == sig2
      # doAssert sig == sig3

  echo "SUCCESS"

test_serialization()
