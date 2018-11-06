# Milagro Crypto
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

## This module reimplements BLS381 pairing scheme introduced here
## https://github.com/lovesh/signature-schemes/blob/master/src/bls/aggr_new.rs.
## Main differences
## 1) Used OS specific CSPRNG.
## 2) BLAKE2b-384 used instead of SHA2-256
## 3) Verification keys got sorted, so there no problem in checking
##    aggregated signatures with verification keys supplied in different
##    order

import algorithm
import nimcrypto/[sysrand, utils, hash, blake2]
import internals, common

type
  SigKey* = object
    x*: BIG_384

  VerKey* = object
    point*: GroupG2

  Signature* = object
    point*: GroupG1

  KeyPair* = object
    sigkey*: SigKey
    verkey*: VerKey

  AggregatedVerKey* = object
    point*: GroupG2

  AggregatedSignature* = object
    point*: GroupG1

  SigPair* = object
    key*: VerKey
    sig*: Signature

const
  RawSignatureKeySize* = MODBYTES_384
  RawVerificationKeySize* = MODBYTES_384 * 4
  RawSignatureSize* = MODBYTES_384 * 2 + 1

proc `$`*(sigkey: SigKey): string {.inline.} =
  ## Return string representation of Signature (Private) key.
  result = $sigkey.x

proc `$`*(verkey: VerKey | AggregatedVerKey): string {.inline.} =
  ## Return string representation of Verification (Public) key.
  var buf: array[MODBYTES_384 * 4, byte]
  toBytes(verkey.point, buf)
  result = toHex(buf, true)

proc `$`*(sig: Signature | AggregatedSignature): string {.inline.} =
  ## Return string representation of ``uncompressed`` signature.
  var buf: array[MODBYTES_384 * 2 + 1, byte]
  toBytes(sig.point, buf)
  result = toHex(buf, true)

proc newSigKey*(): SigKey =
  ## Creates new random Signature (Private) key.
  random(result.x)

proc fromSigKey*(a: SigKey): VerKey =
  ## Create new Verification (Public) key from Signature (Private) key.
  result.point = generator2()
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
  ## Converts Verification key ``verkey`` to serialized form.
  toBytes(verkey.point, result)

proc toRaw*(verkey: VerKey, data: var openarray[byte]) =
  ## Converts Verification key ``verkey`` to serialized form and store it to
  ## ``data``.
  assert(len(data) >= RawVerificationKeySize)
  var buffer = getRaw(verkey)
  copyMem(addr data[0], addr buffer[0], RawVerificationKeySize)

proc getRaw*(sig: Signature): array[RawSignatureSize, byte] =
  ## Converts Signature ``sig`` to serialized form.
  toBytes(sig.point, result)

proc toRaw*(sig: Signature, data: var openarray[byte]) =
  ## Converts Signature ``sig`` to serialized form and store it to ``data``.
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
  if not result.point.fromBytes(data):
    raise newException(ValueError, "Error in signature conversion")

proc initSignature*(data: string): Signature =
  ## Initialize Signature from serialized hexadecimal string ``data``.
  result = initSignature(fromHex(data))

proc newKeyPair*(): KeyPair =
  ## Create new random pair of Signature (Private) and Verification (Public)
  ## keys.
  result.sigkey = newSigKey()
  result.verkey = fromSigKey(result.sigkey)

proc signMessage*(sigkey: SigKey, hash: MDigest[384]): Signature =
  ## Sign 384-bit ``hash`` using Signature (Private) key ``sigkey``.
  var point = hash.mapit()
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
    var gen = generator2()
    var point = hash.mapit()
    var lhs = atePairing(gen, sig.point)
    var rhs = atePairing(verkey.point, point)
    result = (lhs == rhs)

proc verifyMessage*(sig: Signature, msg: openarray[byte],
                    verkey: VerKey): bool {.inline.} =
  ## Verify message ``msg`` using BLAKE2B-384 and using Verification (Public)
  ## key ``verkey``. Returns ``true`` if verification succeeded.
  var hh = blake2_384.digest(msg)
  result = verifyMessage(sig, hh, verkey)

proc hashVerkeyForAggregation(HashType: typedesc, verkey: VerKey,
                              allkeys: openarray[VerKey]): BIG_384 =

  var ctx: HashType
  var serkey: array[RawVerificationKeySize, byte]

  ctx.init()
  serkey = verkey.getRaw()
  ctx.update(serkey)
  for item in allkeys:
    serkey = item.getRaw()
    ctx.update(serkey)
  var digest = ctx.finish()
  discard result.fromBytes(digest.data)

proc cmp(a: VerKey, b: VerKey): int =
  ## Comparison procedure for sorting ``VerKey`` array.
  var s1 = a.getRaw()
  var s2 = b.getRaw()
  for i in 0..<len(s1):
    result = int(s1[i]) - int(s2[i])
    if result < 0:
      result = -1
      return
    elif result > 0:
      result = 1
      return

proc cmp(a: SigPair, b: SigPair): int =
  ## Comparison procedure for sorting ``SigPair`` array.
  var s1 = a.key.getRaw()
  var s2 = b.key.getRaw()
  for i in 0..<len(s1):
    result = int(s1[i]) - int(s2[i])
    if result < 0:
      result = -1
      return
    elif result > 0:
      result = 1
      return

proc initAggregatedKey*(verkeys: openarray[VerKey]): AggregatedVerKey =
  ## Create Aggregated Key from array of verification keys.
  var sortk = sorted(verkeys, cmp)

  result.point.inf()
  for item in sortk:
    var hh = blake2_384.hashVerkeyForAggregation(item, sortk)
    var key = item
    key.point.mul(hh)
    result.point.add(key.point)
    result.point.affine()

proc initAggregatedSignature*(sk: openarray[SigPair]): AggregatedSignature =
  ## Create Aggregated Signature from array of signature and verification keys
  ## pairs.
  var sortsk = sorted(sk, cmp)
  var keys = newSeq[VerKey]()
  var sigs = newSeq[Signature]()

  for item in sortsk:
    keys.add(item.key)

  result.point.inf()
  for item in sortsk:
    var hh = blake2_384.hashVerkeyForAggregation(item.key, keys)
    var sig = item.sig
    sig.point.mul(hh)
    result.point.add(sig.point)
    result.point.affine()

proc verifyMessage*(asig: AggregatedSignature, hash: MDigest[384],
                    akey: AggregatedVerKey): bool =
  ## Verify 384-bit ``hash`` and Aggregated Signature ``sig`` using
  ## Aggregated Verification Key ``akey``.
  ## Returns ``true`` if verification succeeded.
  if asig.point.isinf():
    result = false
  else:
    var gen = generator2()
    var point = hash.mapit()
    var lhs = atePairing(gen, asig.point)
    var rhs = atePairing(akey.point, point)
    result = (lhs == rhs)

proc verifyMessage*[T](asig: AggregatedSignature, msg: openarray[T],
                       akey: AggregatedVerKey): bool =
  ## Verify message ``msg`` and Aggregated Signature ``sig`` using
  ## Aggregated Verification Key ``akey``.
  ## Returns ``true`` if verification succeeded.
  var hh = blake2_384.digest(msg)
  result = verifyMessage(asig, hh, akey)

proc verifyMessage*(sig: AggregatedSignature, hash: MDigest[384],
                    verkeys: openarray[VerKey]): bool =
  ## Verify 384-bit ``hash`` and Aggregated Signature ``sig`` using
  ## array of Verification (Public) Keys ``verkeys``.
  ## Returns ``true`` if verification succeeded.
  var avk = initAggregatedKey(verkeys)
  result = sig.verifyMessage(hash, avk)

proc verifyMessage*[T](sig: AggregatedSignature, msg: openarray[T],
                       verkeys: openarray[VerKey]): bool =
  ## Verify message ``msg`` and Aggregated Signature ``sig`` using
  ## array of Verification (Public) Keys ``verkeys``.
  ## Returns ``true`` if verification succeeded.
  var hh = blake2_384.digest(msg)
  var avk = initAggregatedKey(verkeys)
  result = sig.verifyMessage(hh, avk)
