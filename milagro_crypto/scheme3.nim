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
## 2) Keccak256 is used.
## 3) Serialized signature size is 48 bytes length.

import algorithm
import nimcrypto/[sysrand, utils, hash, keccak]
import internals, common
export common

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

proc getRaw*(verkey: VerKey): array[RawVerificationKeySize, byte] =
  ## Converts Verification Key ``verkey`` to compressed binary form.
  var x, y: BIG384
  let res = verkey.point.get(x, y)
  if res == -1:
    result[0] = result[0] or (1'u8 shl 6)
  else:
    # Determine which mirrored y coordinate this point has
    var ny = nres(y)
    var negy = ny.neg
    negy.norm()
    toBytes(x, result)
    assert((result[0] and 0xE0'u8) == 0'u8)
    if cmp(ny, negy) > 0:
      result[0] = result[0] or (1'u8 shl 5)
  result[0] = result[0] or (1'u8 shl 7)

proc getRawFull*(verkey: VerKey): array[MODBYTES_384 * 2, byte] =
  ## Converts Verification Key ``verkey`` to non-compressed binary form.
  var x, y: BIG_384
  let res = verkey.point.get(x, y)
  if res == -1:
    result[0] = result[0] or (1'u8 shl 6)
  else:
    var buffer: array[MODBYTES_384, byte]
    toBytes(x, buffer)
    copyMem(addr result[0], addr buffer[0], MODBYTES_384)
    toBytes(y, buffer)
    copyMem(addr result[MODBYTES_384], addr buffer[0], MODBYTES_384)

proc toRaw*(verkey: VerKey, data: var openarray[byte]) =
  ## Converts Verification key ``verkey`` to binary form and store it to
  ## ``data``.
  assert(len(data) >= RawVerificationKeySize)
  var buffer = getRaw(verkey)
  copyMem(addr data[0], addr buffer[0], RawVerificationKeySize)

proc fromRaw*(typename: typedesc[VerKey], data: openarray[byte],
              verkey: var VerKey): bool =
  ## Deserialize verification key from compressed binary form and store
  ## result to ``verkey``. Returns ``true`` on success and ``false``
  ## otherwise.
  ## 
  ## Length of ``data`` array must be at least ``RawVerificationKeySize``.
  var buffer: array[MODBYTES_384, byte]
  if len(data) >= RawVerificationKeySize:
    if (data[0] and (1'u8 shl 7)) != 0:
      if (data[0] and (1'u8 shl 6)) != 0:
        # Infinity point
        verkey.point.inf()
        result = true
      else:
        var x: BIG384
        let greatest = (data[0] and (1'u8 shl 5)) != 0'u8
        copyMem(addr buffer[0], unsafeAddr data[0], MODBYTES_384)
        buffer[0] = buffer[0] and 0x1F'u8
        if x.fromBytes(buffer):
          if verkey.point.setx(x, greatest) == 1:
            result = true

proc getRaw*(sig: Signature): array[RawSignatureSize, byte] =
  ## Converts Signature ``sig`` to compressed binary form.
  var x, y: FP2_BLS381
  var b0, b1: BIG384
  var buffer: array[MODBYTES_384, byte]

  if sig.point.get(x, y) == -1:
    result[0] = result[0] or (1'u8 shl 6)
  else:
    FP_BLS381_redc(b0, addr x.b)
    FP_BLS381_redc(b1, addr x.a)
    toBytes(b0, buffer)
    copyMem(addr result[0], addr buffer[0], MODBYTES_384)
    toBytes(b1, buffer)
    copyMem(addr result[MODBYTES_384], addr buffer[0], MODBYTES_384)
    assert((result[0] and 0xE0'u8) == 0'u8)
    var negy = y.neg()
    if cmp(y, negy) > 0:
      result[0] = result[0] or (1'u8 shl 5)
  result[0] = result[0] or (1'u8 shl 7)

proc getRawFull*(sig: Signature): array[MODBYTES_384 * 4, byte] =
  ## Converts Signature ``sig`` to non-compressed binary form.
  var x, y: FP2_BLS381
  var b0, b1: BIG_384
  var a0, a1: BIG_384
  var buffer: array[MODBYTES_384, byte]

  if sig.point.get(x, y) == -1:
    result[0] = result[0] or (1'u8 shl 6)
  else:
    FP_BLS381_redc(b0, addr x.b)
    FP_BLS381_redc(b1, addr x.a)
    FP_BLS381_redc(a0, addr y.b)
    FP_BLS381_redc(a1, addr y.a)

    toBytes(b0, buffer)
    copyMem(addr result[0], addr buffer[0], MODBYTES_384)
    toBytes(b1, buffer)
    copyMem(addr result[MODBYTES_384], addr buffer[0], MODBYTES_384)
    toBytes(a0, buffer)
    copyMem(addr result[MODBYTES_384 * 2], addr buffer[0], MODBYTES_384)
    toBytes(a1, buffer)
    copyMem(addr result[MODBYTES_384 * 3], addr buffer[0], MODBYTES_384)

proc toRaw*(sig: Signature, data: var openarray[byte]) =
  ## Converts Signature ``sig`` to compressed binary form and
  ## store it to ``data``.
  assert(len(data) >= RawSignatureSize)
  var buffer = getRaw(sig)
  copyMem(addr data[0], addr buffer[0], RawSignatureSize)

proc fromRaw*(typename: typedesc[Signature], data: openarray[byte],
              sig: var Signature): bool =
  ## Restore Signature from compressed binary form ``data`` and store
  ## result to ``sig``. Returns ``true`` on success and ``false``
  ## otherwise.
  ## 
  ## Length of ``data`` array must be at least ``RawSignatureSize``.
  var buffer: array[MODBYTES_384, byte]
  if len(data) >= RawSignatureSize:
    # We only support compressed form
    if (data[0] and (1'u8 shl 7)) != 0:
      if (data[0] and (1'u8 shl 6)) != 0:
        # Infinity point
        sig.point.inf()
        result = true
      else:
        var x1, x0: BIG384
        let greatest = (data[0] and (1'u8 shl 5)) != 0'u8
        copyMem(addr buffer[0], unsafeAddr data[0], MODBYTES_384)
        buffer[0] = buffer[0] and 0x1F'u8
        if x1.fromBytes(buffer):
          copyMem(addr buffer[0], unsafeAddr data[MODBYTES_384], MODBYTES_384)
          if x0.fromBytes(buffer):
            var x: FP2_BLS381
            x.fromBigs(x0, x1)
            if sig.point.setx(x, greatest) == 1:
              result = true

# proc hashToG2*(mdigest: MDigest[256], domain: uint64): GroupG2 =
#   var ctx1, ctx2: keccak256
#   var xa, xb: BIG_384
#   var x, one, y: FP2_BLS381
#   var buffer: array[8, byte]
#   EPUTU64(addr buffer, 0, domain)
#   ctx1.init()
#   ctx1.update(buffer)
#   ctx2 = ctx1
#   ctx1.update([0x01'u8])
#   ctx1.update(mdigest.data)
#   var xaDigest = ctx1.finish()
#   ctx2.update([0x02'u8])
#   ctx2.update(mdigest.data)
#   var xbDigest = ctx2.finish()
#   ctx1.clear()
#   ctx2.clear()
#   discard xa.fromBytes(xaDigest.data)
#   discard xb.fromBytes(xbDigest.data)
#   x.fromBigs(xa, xb)
#   one.setOne()
  
#   while true:
#     ECP2_BLS381_rhs(addr y, addr x)
#     if FP2_BLS381_sqrt(addr y, addr y) == 1:
#       discard
#       # ECP2_BLS381_mul(addr x, addr y)

#     if ECP2_BLS381_setx(addr result, addr x) == 1:
#       break
#     add(x, x, one)

proc initSigKey*(data: openarray[byte]): SigKey {.inline.} =
  ## Initialize Signature key from serialized form ``data``.
  if not result.x.fromBytes(data):
    raise newException(ValueError, "Error in signature key conversion")

proc initSigKey*(data: string): SigKey {.inline.} =
  ## Initialize Signature key from serialized hexadecimal string ``data``.
  result = initSigKey(fromHex(data))

proc initVerKey*(data: openarray[byte]): VerKey {.inline.} =
  ## Initialize Verification key from serialized form ``data``.
  if not VerKey.fromRaw(data, result):
    raise newException(ValueError, "Error in verification key conversion")

proc initVerKey*(data: string): VerKey {.inline.} =
  ## Initialize Verification key from serialized hexadecimal string ``data``.
  result = initVerKey(fromHex(data))

proc initSignature*(data: openarray[byte]): Signature {.inline.} =
  ## Initialize Signature from serialized form ``data``.
  ##
  ## Length of ``data`` array must be at least ``RawSignatureSize``.
  if not Signature.fromRaw(data, result):
    raise newException(ValueError, "Error in signature conversion")

proc initSignature*(data: string): Signature {.inline.} =
  ## Initialize Signature from serialized hexadecimal string representation
  ## ``data``.
  result = initSignature(fromHex(data))

proc signMessage*[T](sigkey: SigKey, domain: uint64,
                     hash: MDigest[T]): Signature =
  ## Sign [T]-bit ``hash`` using Signature (Private) key ``sigkey``.
  var point = hash.mapit2()
  point.mul(sigkey.x)
  result.point = point

proc signMessage*[T](sigkey: SigKey, msg: openarray[T]): Signature {.inline.} =
  ## Sign message ``msg`` using KECCAK-256 using Signature (Private) key
  ## ``sigkey``.
  var hh = keccak256.digest(msg)
  result = signMessage(sigkey, 0'u64, hh)

proc verifyMessage*[T](sig: Signature, hash: MDigest[T], domain: uint64,
                       verkey: VerKey): bool =
  ## Verify [T]-bit ``hash`` and signature ``sig`` using Verification (Public)
  ## key ``verkey`` in domain ``domain``. Returns ``true`` if verification
  ## succeeded.
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
  ## Verify message ``msg`` using KECCAK-256 and using Verification (Public)
  ## key ``verkey``. Returns ``true`` if verification succeeded.
  var hh = keccak256.digest(msg)
  result = verifyMessage(sig, hh, 0'u64, verkey)

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

proc `$`*(verkey: VerKey): string {.inline.} =
  ## Return string representation of Verification (Public) key.
  result = toHex(verkey.getRaw(), true)

proc `$`*(sig: Signature): string {.inline.} =
  ## Return string representation of ``uncompressed`` signature.
  result = toHex(sig.getRaw(), true)

proc newKeyPair*(): KeyPair =
  ## Create new random pair of Signature (Private) and Verification (Public)
  ## keys.
  result.sigkey = newSigKey()
  result.verkey = fromSigKey(result.sigkey)

proc generatePoP*(pair: KeyPair): Signature =
  ## Generate Proof Of Possession for key pair ``pair``.
  var rawkey = pair.verkey.getRaw()
  result = pair.sigkey.signMessage(rawkey)

proc verifyPoP*(proof: Signature, vkey: VerKey): bool =
  ## Verifies Proof Of Possession.
  var rawkey = vkey.getRaw()
  result = proof.verifyMessage(rawkey, vkey)
