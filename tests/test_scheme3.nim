# Milagro Crypto
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import unittest, ospaths
import nimcrypto/[sysrand, hash, keccak, utils]
import ../milagro_crypto/scheme3, ../milagro_crypto/hexdump

const messages = [
  "Small msg", "121220888888822111212",
  "Some message to sign",
  "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222",
  " is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
]

const
  domain = 0'u64

suite "[SCHEME3] BLS381 test suite (public interface)":

  test "Simple successful sign/verification tests":
    const messages = [
      "Small msg", "121220888888822111212",
      "Some message to sign",
      "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222"
    ]
    var kp = newKeyPair()
    for msg in messages:
      var sig = kp.sigkey.signMessage(domain, msg)
      check sig.verifyMessage(msg, domain, kp.verkey) == true

  test "Simple failed sign/verification tests":
    var kp = newKeyPair()
    let sk = kp.sigkey
    let vk = kp.verkey
    var msg1 = "Some msg"
    var msg2 = "Other msg"
    var msg3 = ""
    var hctx1, hctx2, hctx3: keccak256
    hctx1.init()
    hctx2.init()
    hctx3.init()
    hctx1.update(msg1)
    hctx2.update(msg2)
    hctx3.update(msg3)
    var sig = sk.signMessage(domain, hctx1)
    check:
      sig.verifyMessage(hctx1, domain, kp.verkey) == true
      sig.verifyMessage(hctx2, domain, kp.verkey) == false
      sig.verifyMessage(hctx3, domain, kp.verkey) == false

  test "Aggregated signature/key tests":
    var kps = [newKeyPair(), newKeyPair(), newKeyPair(), newKeyPair(),
                newKeyPair()]
    for message in messages:
      var hh = keccak256.digest(message)
      var vks = newSeq[VerKey]()
      var svks = newSeq[Signature]()
      for i in 0..<5:
        let kp = kps[i]
        var signature = kp.sigkey.signMessage(domain, message)
        check signature.verifyMessage(message, domain, kp.verkey) == true
        svks.add(signature)
        vks.add(kp.verkey)
      var asig = combine(svks)
      var akey1 = combine(vks)
      var akey2 = combine(vks[0..3])
      check:
        asig.verifyMessage(message, domain, akey1) == true
        asig.verifyMessage(message, domain, akey2) == false

      # replace position of keys
      var temp = vks[2]
      vks[2] = vks[4]
      vks[4] = temp
      var akey3 = combine(vks)
      check asig.verifyMessage(message, domain, akey3) == true

  test "Verification Key compressed serialization test vectors":
    var file = open("tests" / "g1_compressed_valid_test_vectors.dat")
    var expect = newSeq[byte](48000)
    assert(readBytes(file, expect, 0, 48000) == 48000)
    close(file)

    var vk: VerKey
    vk.point.inf()
    for i in 0..<1000:
      var buffer = vk.getRaw()
      check:
        equalMem(addr buffer[0], addr expect[i * 48], MODBYTES_384) == true
      vk.point.add(generator1())

  test "Verification key non-compressed serialization test vectors":
    var file = open("tests" / "g1_uncompressed_valid_test_vectors.dat")
    var expect = newSeq[byte](96000)
    assert(readBytes(file, expect, 0, 96000) == 96000)
    close(file)

    var vk: VerKey
    vk.point.inf()
    for i in 0..<1000:
      var buffer = vk.getRawFull()
      check:
        equalMem(addr buffer[0], addr expect[i * 96], MODBYTES_384) == true
      vk.point.add(generator1())

  test "Signature compressed serialization test vectors":
    var file = open("tests" / "g2_compressed_valid_test_vectors.dat")
    var expect = newSeq[byte](96000)
    assert(readBytes(file, expect, 0, 96000) == 96000)
    close(file)

    var sig: Signature
    sig.point.inf()
    for i in 0..<1000:
      var buffer = sig.getRaw()
      check:
        equalMem(addr buffer[0], addr expect[i * 96], MODBYTES_384 * 2) == true
      sig.point.add(generator2())

  test "Signature non-compressed serialization test vectors":
    var file = open("tests" / "g2_uncompressed_valid_test_vectors.dat")
    var expect = newSeq[byte](192000)
    assert(readBytes(file, expect, 0, 192000) == 192000)
    close(file)

    var sig: Signature
    sig.point.inf()
    for i in 0..<1000:
      var buffer = sig.getRawFull()
      check:
        equalMem(addr buffer[0], addr expect[i * 192], MODBYTES_384 * 4) == true
      sig.point.add(generator2())

  test "Verification Key compressed deserialization test":
    var vk1, vk2: VerKey
    vk1.point.inf()
    for i in 0..<1000:
      var buffer = vk1.getRaw()
      check VerKey.fromRaw(buffer, vk2) == true
      var check = vk2.getRaw()
      check buffer == check
      vk1.point.add(generator1())

  test "Signature compressed deserialization test":
    var sig1, sig2: Signature
    sig1.point.inf()
    for i in 0..<1000:
      var buffer = sig1.getRaw()
      check Signature.fromRaw(buffer, sig2) == true
      var check = sig2.getRaw()
      check buffer == check
      sig1.point.add(generator2())

  test "Sign/Serialize/Deserialize/Verify test":
    var kp = newKeyPair()
    var message = "Simple message"
    for i in 0..<100:
      var desig: Signature
      var idomain = uint64(i)
      var sig = kp.sigkey.signMessage(idomain, message)
      var serialized = sig.getRaw()
      check Signature.fromRaw(serialized, desig) == true
      check desig.verifyMessage(message, idomain, kp.verkey) == true
