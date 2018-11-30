# Milagro Crypto
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

## This module reimplements BLS381 pairing scheme introduced here
## https://github.com/lovesh/signature-schemes/blob/master/src/bls/aggr_old.rs.
## Main differences
## 1) Used OS specific CSPRNG.
## 2) BLAKE2b-384 used instead of SHA2-256
## 3) Serialized signature size is 48 bytes length.

import algorithm
import nimcrypto/[sysrand, utils, hash, blake2]
import internals, common

type
  SigKey* = object
    x*: BIG_384

  VerKey* = object
    point*: GroupG1

  Signature* = object
    point*: GroupG2

  KeyPair* = object
    sigkey*: SigKey
    verkey*: VerKey

const
  RawSignatureKeySize* = MODBYTES_384
  RawVerificationKeySize* = MODBYTES_384
  RawSignatureSize* = MODBYTES_384 * 2

proc newSigKey*(): SigKey =
  ## Creates new random Signature (Private) key.
  randomnum(result.x, CURVE_Order)

proc fromSigKey*(a: SigKey): VerKey =
  ## Obtains Verification (Public) key from Signature (Private) key.
  result.point = generator1()
  result.point.mul(a.x)

proc getRaw*(sigkey: SigKey): array[RawSignatureKeySize, byte] =
  ## Converts Signature key ``sigkey`` to serialized form.
  toBytes(sigkey.x, result)

proc toRaw*(sigkey: SigKey, data: var openarray[byte]) =
  ## Converts Signature key ``sigkey`` to serialized form and store it to
  ## ``data``.
  assert(len(data) >= RawSignatureKeySize)
  var buffer = getRaw(sigkey)
  copyMem(addr data[0], addr buffer[0], RawSignatureKeySize)

# proc getRaw*(verkey: VerKey): array[RawVerificationKeySize, byte] =
#   ## Converts Verification key ``verkey`` to serialized form.
#   var output: array[MODBYTES_384 * 2 + 1, byte]
#   toBytes(verkey.point, output, true)
#   # Check if highest 3 bits are `0`.
#   assert((output[1] and 0xE0'u8) == 0'u8)
#   echo "output = ", output[0]
#   # compressed format marker
#   output[1] = output[1] or (1'u8 shl 7)
#   if verkey.point.isinf():
#     output[1] = output[1] or (1'u8 shl 6)
#   else:
#     if output[0] == 0x02:
#       output[1] = output[1] or (1'u8 shl 5)
#   copyMem(addr result[0], addr output[1], RawVerificationKeySize)

# proc getRaw*(verkey: VerKey): array[RawVerificationKeySize, byte] =
#   var x, y: BIG384
#   if verkey.point.get(x, y) == -1:
#     result[0] = result[0] or 0xC0
#   else:
#     toBytes(x, result)
#     assert((result[0] and 0xE0'u8) == 0'u8)
#     result[0] = result[0] or (1'u8 shl 7)
#     var negy = verkey.point.y.neg()
#     if cmp(verkey.point.y, negy) > 0:
#       result[0] = result[0] or (1'u8 shl 5)

proc getRaw*(verkey: VerKey): array[RawVerificationKeySize, byte] =
  ## Serialization in compressed form.
  var x, y: BIG384
  let res = verkey.point.get(x, y)
  if res == -1:
    result[0] = result[0] or 0xC0
  else:
    echo res
    toBytes(x, result)
    assert((result[0] and 0xE0'u8) == 0'u8)
    result[0] = result[0] or (1'u8 shl 7)

proc getRawFull*(verkey: VerKey): array[RawVerificationKeySize * 2, byte] =
  ## This is serialization in non-compressed form.
  var x, y: BIG384
  var buffer: array[MODBYTES_384, byte]
  let res = verkey.point.get(x, y)
  if res == -1:
    result[0] = result[0] or 0xC0
  else:
    var posy0 = verkey.point.y
    var posy1 = posy0
    var negy0 = neg(posy0)
    var negy1 = negy0
    norm(negy1)
    norm(posy1)
    echo "nn(y) and nn(neg(y)): ", cmp(posy0, negy0)
    echo "nn(y) and n(neg(y)): ", cmp(posy0, negy1)
    echo "n(y) and nn(neg(y)): ", cmp(posy1, negy0)
    echo "n(y) and n(neg(y)): ", cmp(posy1, negy1)
    toBytes(x, buffer)
    copyMem(addr result[0], addr buffer[0], MODBYTES_384)
    toBytes(y, buffer)
    copyMem(addr result[MODBYTES_384], addr buffer[0], MODBYTES_384)
    # assert((result[0] and 0xE0'u8) == 0'u8)
    # result[0] = result[0] or (1'u8 shl 7)

proc toRaw*(verkey: VerKey, data: var openarray[byte]) =
  ## Converts Verification key ``verkey`` to serialized form and store it to
  ## ``data``.
  assert(len(data) >= RawVerificationKeySize)
  var buffer = getRaw(verkey)
  copyMem(addr data[0], addr buffer[0], RawVerificationKeySize)

proc getRaw*(sig: Signature): array[RawSignatureSize, byte] =
  ## Converts Signature ``sig`` to compressed serialized form.
  var x, y: FP2_BLS381
  var b0, b1: BIG_384
  var buffer: array[MODBYTES_384, byte]

  if sig.point.get(x, y) == -1:
    result[0] = result[0] or 0xC0
  else:
    FP_BLS381_redc(b0, addr x.b)
    FP_BLS381_redc(b1, addr x.a)
    toBytes(b0, buffer)
    copyMem(addr result[0], addr buffer[0], MODBYTES_384)
    toBytes(b1, buffer)
    copyMem(addr result[MODBYTES_384], addr buffer[0], MODBYTES_384)
    assert((result[0] and 0xE0'u8) == 0'u8)
    result[0] = result[0] or (1'u8 shl 7)
    var negy = y.neg()
    if cmp(y, negy) > 0:
      result[0] = result[0] or (1'u8 shl 5)

proc toRaw*(sig: Signature, data: var openarray[byte]) =
  ## Converts Signature ``sig`` to compressed serialized form and
  ## store it to ``data``.
  assert(len(data) >= RawSignatureSize)
  var buffer = getRaw(sig)
  copyMem(addr data[0], addr buffer[0], RawSignatureSize)

proc initSigKey*(data: openarray[byte]): SigKey =
  ## Initialize Signature key from serialized form ``data``.
  if not result.x.fromBytes(data):
    raise newException(ValueError, "Error in signature key conversion")

proc initSigKey*(data: string): SigKey =
  ## Initialize Signature key from serialized hexadecimal string ``data``.
  result = initSigKey(fromHex(data))

proc initVerKey*(data: openarray[byte]): VerKey =
  ## Initialize Verification key from serialized form ``data``.
  if not result.point.fromBytes(data):
    raise newException(ValueError, "Error in verification key conversion")

proc initVerKey*(data: string): VerKey =
  ## Initialize Verification key from serialized hexadecimal string ``data``.
  result = initVerKey(fromHex(data))

proc initSignature*(data: openarray[byte]): Signature =
  ## Initialize Signature from serialized form ``data``.
  ##
  ## Length of ``data`` array must be at least ``RawSignatureSize``.
  var buffer: array[MODBYTES_384 + 1, byte]
  if len(data) < RawSignatureSize:
    raise newException(ValueError, "Invalid signature")
  let marker = (data[0] and 0xE0'u8) shr 5
  if marker notin {0x02'u8, 0x03'u8}:
    raise newException(ValueError, "Invalid signature")
  buffer[0] = marker
  copyMem(addr buffer[1], unsafeAddr data[0], RawSignatureSize)
  buffer[1] = buffer[1] and 0x1F'u8
  if not result.point.fromBytes(buffer):
    raise newException(ValueError, "Error in signature conversion")

proc initSignature*(data: string): Signature =
  ## Initialize Signature from serialized hexadecimal string representation
  ## ``data``.
  result = initSignature(fromHex(data))

proc signMessage*(sigkey: SigKey, hash: MDigest[384]): Signature =
  ## Sign 384-bit ``hash`` using Signature (Private) key ``sigkey``.
  var point = hash.mapit2()
  point.mul(sigkey.x)
  result.point = point

proc signMessage*[T](sigkey: SigKey, msg: openarray[T]): Signature {.inline.} =
  ## Sign message ``msg`` using BLAKE2B-384 using Signature (Private) key
  ## ``sigkey``.
  var hh = blake2_384.digest(msg)
  result = signMessage(sigkey, hh)

proc verifyMessage*(sig: Signature, hash: MDigest[384], verkey: VerKey): bool =
  ## Verify 384-bit ``hash`` and signature ``sig`` using Verification (Public)
  ## key ``verkey``. Returns ``true`` if verification succeeded.
  if sig.point.isinf():
    result = false
  else:
    var gen = generator1()
    var point = hash.mapit2()
    var lhs = atePairing(sig.point, gen)
    var rhs = atePairing(point, verkey.point)
    result = (lhs == rhs)

proc verifyMessage*[T](sig: Signature, msg: openarray[T],
                       verkey: VerKey): bool {.inline.} =
  ## Verify message ``msg`` using BLAKE2B-384 and using Verification (Public)
  ## key ``verkey``. Returns ``true`` if verification succeeded.
  var hh = blake2_384.digest(msg)
  result = verifyMessage(sig, hh, verkey)

proc combine*(sig1: var Signature, sig2: Signature) =
  ## Aggregates signature ``sig2`` into ``sig1``.
  add(sig1.point, sig2.point)

proc combine*(key1: var VerKey, key2: VerKey) =
  ## Aggregates verification key ``key2`` into ``key1``.
  add(key1.point, key2.point)

proc combine*(keys: openarray[VerKey]): VerKey =
  ## Aggregates array of verification keys ``keys`` and return aggregated
  ## verification key.
  ##
  ## Array ``keys`` must not be empty!
  doAssert(len(keys) > 0)
  result = keys[0]
  for i in 1..<len(keys):
    add(result.point, keys[i].point)

proc combine*(sigs: openarray[Signature]): Signature =
  ## Aggregates array of signatures ``sigs`` and return aggregated signature.
  ##
  ## Array ``sigs`` must not be empty!
  doAssert(len(sigs) > 0)
  result = sigs[0]
  for i in 1..<len(sigs):
    add(result.point, sigs[i].point)

proc `==`*(sig1, sig2: Signature): bool =
  ## Compares two signatures ``sig1`` and ``sig2``.
  ## Returns ``true`` if signatures are equal.
  result = (sig1.point == sig2.point)

proc `==`*(key1, key2: VerKey): bool =
  ## Compares two verification keys ``key1`` and ``key2``.
  ## Returns ``true`` if verification keys are equal.
  result = (key1.point == key2.point)

proc `$`*(sigkey: SigKey): string {.inline.} =
  ## Return string representation of Signature (Private) key.
  result = $sigkey.x

# proc `$`*(verkey: VerKey): string {.inline.} =
#   ## Return string representation of Verification (Public) key.
#   var buf: array[MODBYTES_384 * 4, byte]
#   toBytes(verkey.point, buf)
#   result = toHex(buf, true)

# proc `$`*(sig: Signature): string {.inline.} =
#   ## Return string representation of ``uncompressed`` signature.
#   var buf: array[MODBYTES_384, byte]
#   sig.toRaw(buf)
#   result = toHex(buf, true)

proc newKeyPair*(): KeyPair =
  ## Create new random pair of Signature (Private) and Verification (Public)
  ## keys.
  result.sigkey = newSigKey()
  result.verkey = fromSigKey(result.sigkey)

# proc generatePoP*(pair: KeyPair): Signature =
#   ## Generate Proof Of Possession for key pair ``pair``.
#   var rawkey = pair.verkey.getRaw()
#   result = pair.sigkey.signMessage(rawkey)

# proc verifyPoP*(proof: Signature, vkey: VerKey): bool =
#   ## Verifies Proof Of Possession.
#   var rawkey = vkey.getRaw()
#   result = proof.verifyMessage(rawkey, vkey)

when isMainModule:
  import nimcrypto, hexdump

  ## XXX
  ## This is just dump procedure from rust implementation test vectors
  ## you can uncomment it and execute
  
  # block:
  #   var file = open("g1_compressed_valid_test_vectors.dat")
  #   var expect = newSeq[byte](48000)
  #   assert(readBytes(file, expect, 0, 48000) == 48000)
  #   close(file)
  #   for i in 0..<10:
  #     let offset = i * 48
  #     let ch = expect[offset] and (1'u8 shl 5)
  #     echo ch
  #     echo dumpHex(expect.toOpenArray(offset, offset + 47))


  block:
    var a: ECP_BLS381
    inf(a)
    var vk: VerKey
    vk.point = a
    for i in 0..<10:
      echo dumpHex(vk.getRawFull())
      add(vk.point, generator1())

  ## This is full test of G2 serialization
  ## 
  
  # block:
  #   var file = open("g2_compressed_valid_test_vectors.dat")
  #   var expect = newSeq[byte](96000)
  #   assert(readBytes(file, expect, 0, 96000) == 96000)
  #   close(file)
  #   var a: ECP2_BLS381
  #   inf(a)
  #   var sig: Signature
  #   sig.point = a
  #   for i in 0..<1000:
  #     echo i
  #     var check = sig.getRaw()
  #     assert(equalMem(addr check[0], addr expect[i * 96], 96) == true)
  #     add(sig.point, generator2())


  # var pair = newKeyPair()
  # var h = blake2_384.digest("Hello world!")
  # var h1 = blake2_384.digest("Hello world+")
  # var sig = signMessage(pair.sigkey, h)

  # echo "original ", verifyMessage(sig, h, pair.verkey)
  # echo "original ", verifyMessage(sig, h1, pair.verkey)

  # # echo "original y"
  # # echo repr sig.point.y
  # var x0, y0: FP2_BLS381
  # var x1, y1: FP2_BLS381
  # echo "result = ", sig.point.get(x0, y0)

  # var re: ECP2_BLS381
  # echo "result = ", setx(re, x0)
  # # echo "calculated y"
  # # echo repr re.y

  # # echo "result = ", re.get(x1, y1)
  # # var negy = neg(re.y)
  # # echo "negative y"
  # # echo repr negy

  # # echo cmp(y0, re.y)
  # # echo cmp(y0, negy)

  # var rsig: Signature
  # rsig.point = re

  # echo "restored ", verifyMessage(sig, h, pair.verkey)
  # echo "restored ", verifyMessage(sig, h1, pair.verkey)





  # # echo "original"
  # # echo repr x
  # # echo "negative"
  # # var negx = neg(x)
  # # echo repr negx

  # # echo "negative normalized"
  # # FP2_BLS381_norm(addr negx)
  # # echo repr negx

  # # echo cmp(orx, orx)
  # # echo cmp(orx, negx)
  # echo cmp(negx, orx)

  # var newx = neg(negx)
  # echo "positive"
  # echo repr newx
  # FP2_BLS381_norm(addr newx)
  # echo "positive normalized"
  # echo repr newx

  # echo cmp(orx, newx)