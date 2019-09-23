# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.
import nimcrypto/[sysrand, utils, hash, sha2]
import stew/endians2
import milagro, common

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

  BLSError* = object of CatchableError
  BLSDecodeError* = object of BLSError
  BLSEncodeError* = object of BLSError

const
  RawSignatureKeySize* = MODBYTES_384
  RawVerificationKeySize* = MODBYTES_384
  RawSignatureSize* = MODBYTES_384 * 2

proc init*(v: VerKey | Signature) =
  ## Initialize ``VerificationKey``, ``Signature`` to the infinitiy point
  v.point.inf()

proc init*(T: VerKey | Signature): auto =
  ## Initialize ``VerificationKey``, ``Signature`` to the infinitiy point
  var ret: T
  ret.init()
  ret

proc init*[T: SigKey|VerKey|Signature](obj: var T,
                                       data: openarray[byte]): bool {.inline.} =
  ## Initialize ``SignatureKey``, ``VerificationKey`` or ``Signature`` from
  ## raw binary representation ``data``.
  ##
  ## Procedure returns ``true`` on success and ``false`` otherwise.
  when T is SigKey:
    result = obj.x.fromBytes(data)
  else:
    result = obj.point.fromBytes(data)

proc init*[T: SigKey|VerKey|Signature](obj: var T,
                                       data: string): bool {.inline.} =
  ## Initialize ``SignatureKey``, ``VerificationKey`` or ``Signature`` from
  ## hexadecimal string representation ``data``
  ##
  ## Procedure returns ``true`` on success and ``false`` otherwise.
  when T is SigKey:
    result = obj.x.fromHex(data)
  else:
    result = obj.point.fromHex(data)

proc init*[T: SigKey|VerKey|Signature](t: typedesc[T],
                                       data: openarray[byte]): T {.inline.} =
  ## Initialize ``SignatureKey``, ``VerificationKey`` or ``Signature`` from
  ## raw binary representation ``data`` and return constructed object.
  when T is SigKey:
    let res = result.x.fromBytes(data)
  else:
    let res = result.point.fromBytes(data)
  if not res:
    raise newException(BLSDecodeError, "Initialization error")

proc init*[T: SigKey|VerKey|Signature](t: typedesc[T],
                                       data: string): T {.inline.} =
  ## Initialize ``SignatureKey``, ``VerificationKey`` or ``Signature`` from
  ## hexadecimal string representation ``data`` and return constructed object.
  when T is SigKey:
    let res = result.x.fromHex(data)
  else:
    let res = result.point.fromHex(data)
  if not res:
    raise newException(BLSDecodeError, "Initialization error!")

proc random*(t: typedesc[SigKey]): SigKey {.inline.} =
  ## Creates new random Signature (Private) key.
  randomnum(result.x, CURVE_Order)

proc random*(t: typedesc[KeyPair]): KeyPair {.inline.} =
  ## Create new random pair of Signature (Private) and Verification (Public)
  ## keys.
  result.sigkey = SigKey.random()
  result.verkey = result.sigkey.getKey()

proc getKey*(a: SigKey): VerKey {.inline.} =
  ## Obtains Verification (Public) key from Signature (Private) key.
  result.point = generator1()
  result.point.mul(a.x)

proc toBytes*[T: SigKey|VerKey|Signature](obj: T,
                                          data: var openarray[byte]): bool =
  ## Serialize ``SignatureKey``, ``VerificationKey`` or ``Signature`` to raw
  ## binary form and store it to ``data``.
  ##
  ## For ``SigKey`` length of ``data`` array must be at least
  ## ``RawSignatureKeySize``.
  ##
  ## For ``VerKey`` length of ``data`` array must be at least
  ## ``RawVerificationKeySize``.
  ##
  ## For ``Signature`` length of ``data`` array must be at least
  ## ``RawSignatureSize``.
  ##
  ## Procedure returns ``true`` if serialization successfull, ``false``
  ## otherwise.
  when T is SigKey:
    result = obj.x.toBytes(data)
  else:
    result = obj.point.toBytes(data)

proc getBytes*(sigkey: SigKey): array[RawSignatureKeySize, byte] =
  ## Serialize Signature Key ``sigkey`` to raw binary form and return it.
  discard toBytes(sigkey.x, result)

proc getBytes*(verkey: VerKey): array[RawVerificationKeySize, byte] =
  ## Serialize Verification Key ``verkey`` to raw binary form and return it.
  discard toBytes(verkey.point, result)

proc getBytes*(sig: Signature): array[RawSignatureSize, byte] =
  ## Serialize Signature ``sig`` to raw binary form and return it.
  discard toBytes(sig.point, result)

proc toHex*[T: SigKey|VerKey|Signature](obj: T): string =
  ## Return hexadecimal string representation of ``SignatureKey``,
  ## ``VerificationKey`` or ``Signature``.
  when T is SigKey:
    result = obj.x.toHex()
  else:
    result = obj.point.toHex()

proc sign*(sigkey: SigKey, domain: Domain, mdctx: sha256): Signature =
  ## Sign sha2-256 context using Signature Key ``sigkey`` over domain
  ## ``domain``.
  var point = hashToG2(mdctx, domain)
  point.mul(sigkey.x)
  result.point = point

proc sign*(
    sigkey: SigKey, domain: uint64, mdctx: sha256): Signature {.deprecated.} =
  sign(sigkey, domain.toBytesBE(), mdctx)

proc sign*[T: byte|char](sigkey: SigKey, domain: Domain,
                         message: openarray[T]): Signature =
  ## Sign message ``message`` using Signature Key ``sigkey`` over domain
  ## ``domain``.
  var mdctx: sha256
  mdctx.init()
  mdctx.update(message)
  result = sign(sigkey, domain, mdctx)
  mdctx.clear()

proc sign*[T: byte|char](sigkey: SigKey, domain: uint64,
                         message: openarray[T]): Signature {.deprecated.} =
  sign(sigkey, domain.toBytesBE(), message)

# proc verify*(sig: Signature, mdctx: sha256, domain: uint64,
#              verkey: VerKey): bool =
#   ## Verify signature ``sig`` using Verification Key ``verkey`` and sha2-256
#   ## context ``mdctx`` over domain ``domain``.
#   ##
#   ## Returns ``true`` if message verification succeeded, ``false`` if
#   ## verification failed.
#   if sig.point.isinf():
#     result = false
#   else:
#     var gen = generator1()
#     var point = hashToG2(mdctx, domain)
#     var lhs = atePairing(sig.point, gen)
#     var rhs = atePairing(point, verkey.point)
#     result = (lhs == rhs)

# proc verify2*(sig: Signature, mdctx: sha256, domain: uint64,
#                verkey: VerKey): bool =
#   if sig.point.isinf():
#     result = false
#   else:
#     var gen = generator1()
#     var point = hashToG2(mdctx, domain)
#     result = doublePairing(sig.point, gen, point, verkey.point)

proc verify*(sig: Signature, mdctx: sha256, domain: Domain,
             verkey: VerKey): bool =
  ## Verify signature ``sig`` using Verification Key ``verkey`` and sha2-256
  ## context ``mdctx`` over domain ``domain``.
  ##
  ## Returns ``true`` if message verification succeeded, ``false`` if
  ## verification failed.
  if sig.point.isinf():
    result = false
  else:
    var gen = generator1()
    var point = hashToG2(mdctx, domain)
    result = multiPairing(sig.point, gen, point, verkey.point)

proc verify*(sig: Signature, mdctx: sha256, domain: uint64,
             verkey: VerKey): bool {.deprecated.} =
  verify(sig, mdctx, domain.toBytesBE(), verkey)

proc verify*[T: byte|char](sig: Signature, message: openarray[T],
                           domain: Domain, verkey: VerKey): bool {.inline.} =
  ## Verify signature ``sig`` using Verification Key ``verkey`` and message
  ## ``message`` over domain ``domain``.
  ##
  ## Return ``true`` if message verification succeeded, ``false`` if
  ## verification failed.
  var mdctx: sha256
  mdctx.init()
  mdctx.update(message)
  result = verify(sig, mdctx, domain, verkey)
  mdctx.clear()

proc verify*[T: byte|char](sig: Signature, message: openarray[T],
                           domain: uint64, verkey: VerKey): bool {.deprecated.} =
  verify(sig, message, domain.toBytesBE(), verkey)

proc combine*(sig1: var Signature, sig2: Signature) =
  ## Aggregates signature ``sig2`` into ``sig1``.
  add(sig1.point, sig2.point)

proc combine*(sigs: openarray[Signature]): Signature =
  ## Aggregates array of signatures ``sigs`` and return aggregated signature.
  ##
  ## Array ``sigs`` must not be empty!
  doAssert(len(sigs) > 0)
  result = sigs[0]
  for i in 1..<len(sigs):
    add(result.point, sigs[i].point)

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
  result = toHex(verkey.getBytes(), true)

proc `$`*(sig: Signature): string {.inline.} =
  ## Return string representation of ``uncompressed`` signature.
  result = toHex(sig.getBytes(), true)

proc generatePoP*(pair: KeyPair): Signature =
  ## Generate Proof Of Possession for key pair ``pair``.
  var rawkey = pair.verkey.getBytes()
  result = pair.sigkey.sign(0'u64, rawkey)

proc verifyPoP*(proof: Signature, verkey: VerKey): bool =
  ## Verifies Proof Of Possession.
  var rawkey = verkey.getBytes()
  result = proof.verify(rawkey, 0'u64, verkey)
