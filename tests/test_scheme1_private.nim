# Milagro Crypto
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import unittest
import nimcrypto/[sysrand, hash, blake2, utils]
import ../src/milagro_internals
include ../src/scheme1

suite "BLS381 test suite (private procs)":
  test "Simple infinity signature test":
    var kp = newKeyPair()
    let vk = kp.verkey
    var sk = kp.sigkey
    var msg = "Small msg"
    var hash = blake2_384.digest(msg)

    var sig = sk.signMessage(hash)
    sig.point.inf()
    check sig.verifyMessage(hash, kp.verkey) == false

  test "Aggregated signature/key infinity test":
    var keypair1 = newKeyPair()
    var keypair2 = newKeyPair()
    var hh = blake2_384.digest("Small msg")
    var asig: AggregatedSignature
    asig.point.inf()
    check asig.verifyMessage(hh, [keypair1.verkey, keypair2.verkey]) == false
