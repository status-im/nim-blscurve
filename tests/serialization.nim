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
      sk{.noInit.}: SecretKey
      pk{.noInit.}: PublicKey
      pk_uncomp{.noInit.}: array[96, byte]
      pk_comp{.noInit.}: array[48, byte]
    let ok = sk.fromHex(seckey)
    doAssert ok
    let ok2 = pk.publicFromSecret(sk)
    doAssert ok2

    # Serialize compressed and uncompressed
    doAssert pk_comp.serialize(pk)
    doAssert pk_uncomp.serialize(pk)

    var pk2{.noInit.}: PublicKey
    var pk3{.noInit.}: PublicKey

    doAssert pk2.fromBytes(pk_comp)
    doAssert pk3.fromBytes(pk_uncomp)

    doAssert pk == pk2
    doAssert pk == pk3

  # Signature serialization
  # -----------------------
  for seckey in seckeys:
    var
      sk{.noInit.}: SecretKey
      pk{.noInit.}: PublicKey
      pk_uncomp{.noInit.}: array[96, byte]
      pk_comp{.noInit.}: array[48, byte]
    let ok = sk.fromHex(seckey)
    doAssert ok
    let ok2 = pk.publicFromSecret(sk)
    doAssert ok2

    for msg in msgs:
      let sig = sk.sign(msg)

      var
        sig_uncomp{.noInit.}: array[192, byte]
        sig_comp{.noInit.}: array[96, byte]

      # Serialize compressed and uncompressed
      doAssert sig_comp.serialize(sig)
      doAssert sig_uncomp.serialize(sig)

      var sig2{.noInit.}: Signature
      var sig3{.noInit.}: Signature

      doAssert sig2.fromBytes(sig_comp)
      doAssert sig3.fromBytes(sig_uncomp)

      doAssert sig == sig2
      doAssert sig == sig3

  echo "SUCCESS"

test_serialization()
