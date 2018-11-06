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
import ../milagro_crypto/[internals, common, scheme2]

suite "[SCHEME2] BLS381 test suite (private procs)":
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
    var asig: Signature
    var akey: VerKey
    asig.point.inf()
    akey = keypair1.verkey
    akey.combine(keypair2.verkey)
    check asig.verifyMessage(hh, akey) == false
