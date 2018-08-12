# Milagro Crypto
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import unittest
import nimcrypto/[sysrand, hash, keccak]
import ../src/[milagro_internals, common]

when isMainModule:
  suite "Simple signature/verification test suite":
    
    test "Successful sign/verification tests":
      const messages = [
        "Small msg", "121220888888822111212",
        "Some message to sign",
        "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222"
      ]
      var kp = newKeyPair()
      for msg in messages:
        var hash = keccak256.digest(msg)
        var sig = kp.sigkey.signMessage(hash)
        check sig.verifyMessage(hash, kp.verkey) == true
    
    test "Failed sign/verification tests":
      var kp = newKeyPair()
      let sk = kp.sigkey
      let vk = kp.verkey

      var msg1 = "Some msg"
      var msg2 = "Other msg"
      var msg3 = ""
      let hash1 = keccak256.digest(msg1)
      let hash2 = keccak256.digest(msg2)
      let hash3 = keccak256.digest(msg3)

      var sig = sk.signMessage(hash1)

      check:
        sig.verifyMessage(hash1, kp.verkey) == true
        sig.verifyMessage(hash2, kp.verkey) == false
        sig.verifyMessage(hash3, kp.verkey) == false

    test "Infinity test":
      var kp = newKeyPair()
      let vk = kp.verkey
      var sk = kp.sigkey
      var msg = "Small msg"
      var hash = keccak256.digest(msg)

      var sig = sk.signMessage(hash)
      sig.point.inf()
      check sig.verifyMessage(hash, kp.verkey) == false
