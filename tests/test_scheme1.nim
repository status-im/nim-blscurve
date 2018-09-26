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
import ../src/scheme1

const messages = [
  "Small msg", "121220888888822111212",
  "Some message to sign",
  "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222",
  " is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
]

suite "BLS381 test suite (public interface)":
  test "Simple successful sign/verification tests":
    const messages = [
      "Small msg", "121220888888822111212",
      "Some message to sign",
      "Some message to sign, making it bigger, ......, still bigger........................, not some entropy, hu2jnnddsssiu8921n ckhddss2222"
    ]
    var kp = newKeyPair()
    for msg in messages:
      var hash = blake2_384.digest(msg)
      var sig = kp.sigkey.signMessage(hash)
      check sig.verifyMessage(hash, kp.verkey) == true

  test "Simple failed sign/verification tests":
    var kp = newKeyPair()
    let sk = kp.sigkey
    let vk = kp.verkey
    var msg1 = "Some msg"
    var msg2 = "Other msg"
    var msg3 = ""
    let hash1 = blake2_384.digest(msg1)
    let hash2 = blake2_384.digest(msg2)
    let hash3 = blake2_384.digest(msg3)
    var sig = sk.signMessage(hash1)
    check:
      sig.verifyMessage(hash1, kp.verkey) == true
      sig.verifyMessage(hash2, kp.verkey) == false
      sig.verifyMessage(hash3, kp.verkey) == false

  test "Aggregated signature/key tests":
    var kps = [newKeyPair(), newKeyPair(), newKeyPair(), newKeyPair(),
                newKeyPair()]
    for message in messages:
      var hh = blake2_384.digest(message)
      var vks = newSeq[VerKey]()
      var svks = newSeq[SigPair]()
      for i in 0..<5:
        let kp = kps[i]
        var signature = kp.sigkey.signMessage(hh)
        check signature.verifyMessage(hh, kp.verkey) == true
        svks.add(SigPair(sig: signature, key: kp.verkey))
        vks.add(kp.verkey)
      var asig = initAggregatedSignature(svks)
      var akey = initAggregatedKey(vks)
      check:
        asig.verifyMessage(hh, vks) == true
        asig.verifyMessage(hh, akey) == true
        asig.verifyMessage(hh, vks[0..3]) == false
      # replace position of keys
      var temp = vks[2]
      vks[2] = vks[4]
      vks[4] = temp
      check asig.verifyMessage(hh, vks) == true

  test "Signature Key serialize/deserialize test":
    for i in 0..<100:
      var rawbuf: array[RawSignatureKeySize, byte]
      var key = newSigKey()
      var expectkey = $key
      var rawkey1 = key.getRaw()
      key.toRaw(rawbuf)
      var ckhex1 = toHex(rawkey1, true)
      var ckhex2 = toHex(rawbuf, true)
      var nk1 = initSigKey(ckhex1)
      var nk2 = initSigKey(rawbuf)
      check:
        expectkey == ckhex1
        expectkey == ckhex2
        expectkey == $nk1
        expectkey == $nk2

  test "Verification Key serialize/deserialize test":
    for i in 0..<100:
      var rawbuf: array[RawVerificationKeySize, byte]
      var skey = newSigKey()
      var key = skey.fromSigKey()
      var expectkey = $key
      var rawkey1 = key.getRaw()
      key.toRaw(rawbuf)
      var ckhex1 = toHex(rawkey1, true)
      var ckhex2 = toHex(rawbuf, true)
      var nk1 = initVerKey(ckhex1)
      var nk2 = initVerKey(rawbuf)
      check:
        expectkey == ckhex1
        expectkey == ckhex2
        expectkey == $nk1
        expectkey == $nk2

  test "Signature serialize/deserialize test":
    var hh = blake2_384.digest("Simple message")
    for i in 0..<100:
      var rawbuf: array[RawSignatureSize, byte]
      var skey = newSigKey()
      var key = skey.fromSigKey()
      var sig = skey.signMessage(hh)
      var expectsig = $sig
      var rawsig1 = sig.getRaw()
      sig.toRaw(rawbuf)
      var ckhex1 = toHex(rawsig1, true)
      var ckhex2 = toHex(rawbuf, true)
      var ns1 = initSignature(ckhex1)
      var ns2 = initSignature(rawbuf)
      check:
        expectsig == ckhex1
        expectsig == ckhex2
        expectsig == $ns1
        expectsig == $ns2
