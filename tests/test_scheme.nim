# Milagro Crypto
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.
import unittest, ospaths
import nimcrypto/[sysrand, hash, sha2, utils]
import ../blscurve/bls_old_spec, ../blscurve/common

const messages = [
  "Small msg", "121220888888822111212",
  "Some message to sign",
  "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222",
  " is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
]

const
  domain = 0'u64

suite "[Before IETF standard] BLS381-12 test suite (public interface)":

  test "Simple successful sign/verification tests":
    var kp = KeyPair.random()
    for msg in messages:
      var sig = kp.sigkey.sign(domain, msg)
      check sig.verify(msg, domain, kp.verkey) == true

  test "Simple infinity signature test":
    var kp = KeyPair.random()
    let vk = kp.verkey
    var sk = kp.sigkey
    var msg = "Small msg"
    let domain = 0'u64
    var sig = sk.sign(domain, msg)
    sig.point.inf()
    check sig.verify(msg, domain, kp.verkey) == false

  test "Aggregated signature/key infinity test":
    var keypair1 = KeyPair.random()
    var keypair2 = KeyPair.random()
    var msg = "Small msg"
    let domain = 0'u64
    var asig: Signature
    var akey: VerKey
    asig.point.inf()
    akey = keypair1.verkey
    akey.combine(keypair2.verkey)
    check asig.verify(msg, domain, akey) == false

  test "Simple failed sign/verification tests":
    var kp = KeyPair.random()
    let sk = kp.sigkey
    let vk = kp.verkey
    var msg1 = "Some msg"
    var msg2 = "Other msg"
    var msg3 = ""
    var hctx1, hctx2, hctx3: sha256
    hctx1.init()
    hctx2.init()
    hctx3.init()
    hctx1.update(msg1)
    hctx2.update(msg2)
    hctx3.update(msg3)
    var sig = sk.sign(domain, hctx1)
    check:
      sig.verify(hctx1, domain, kp.verkey) == true
      sig.verify(hctx2, domain, kp.verkey) == false
      sig.verify(hctx3, domain, kp.verkey) == false

  test "Aggregated signature/key tests":
    var kps = [KeyPair.random(), KeyPair.random(), KeyPair.random(),
               KeyPair.random(), KeyPair.random()]
    for message in messages:
      var hh = sha256.digest(message)
      var vks = newSeq[VerKey]()
      var svks = newSeq[Signature]()
      for i in 0..<5:
        let kp = kps[i]
        var signature = kp.sigkey.sign(domain, message)
        check signature.verify(message, domain, kp.verkey) == true
        svks.add(signature)
        vks.add(kp.verkey)
      var asig = combine(svks)
      var akey1 = combine(vks)
      var akey2 = combine(vks[0..3])
      check:
        asig.verify(message, domain, akey1) == true
        asig.verify(message, domain, akey2) == false

      # replace position of keys
      var temp = vks[2]
      vks[2] = vks[4]
      vks[4] = temp
      var akey3 = combine(vks)
      check asig.verify(message, domain, akey3) == true

  test "Verification Key compressed deserialization test":
    var vk1, vk2: VerKey
    vk1.point.inf()
    for i in 0..<1000:
      var buffer = vk1.getBytes()
      check vk2.init(buffer) == true
      var chk = vk2.getBytes()
      check buffer == chk
      vk1.point.add(generator1())

  test "Signature compressed deserialization test":
    var sig1, sig2: Signature
    sig1.point.inf()
    for i in 0..<1000:
      var buffer = sig1.getBytes()
      check sig2.init(buffer) == true
      var chk = sig2.getBytes()
      check buffer == chk
      sig1.point.add(generator2())

  test "Sign/Serialize/Deserialize/Verify test":
    var kp = KeyPair.random()
    var message = "Simple message"
    for i in 0..<100:
      var desig: Signature
      var idomain = uint64(i)
      var sig = kp.sigkey.sign(idomain, message)
      var serialized = sig.getBytes()
      check desig.init(serialized) == true
      check desig.verify(message, idomain, kp.verkey) == true
