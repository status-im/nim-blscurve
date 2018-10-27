# Milagro Crypto
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

## This module reimplements BLS381 pairing scheme introduced here
## https://github.com/lovesh/signature-schemes.
## Main differences
## 1) Used OS specific CSPRNG.
## 2) BLAKE2b-384 used instead of SHA2-256
## 3) Verification keys got sorted, so there no problem in checking
##    aggregated signatures with verification keys supplied in different
##    order

import algorithm
import nimcrypto/[sysrand, utils, hash, blake2]
import milagro_internals

type
  SigKey* = object
    x*: BIG_384_29

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
  RawSignatureKeySize* = MODBYTES_384_29
  RawVerificationKeySize* = MODBYTES_384_29 * 4
  RawSignatureSize* = MODBYTES_384_29 * 2 + 1

proc zero(a: var BIG_384_29) {.inline.} =
  ## Make big integer ``a`` be zero.
  for i in 0..<len(a):
    a[i] = 0

proc bitsCount(a: BIG_384_29): int {.inline.} =
  ## Returns number of bits in big integer ``a``.
  result = BIG_384_29_nbits(a)

proc copy(dst: var BIG_384_29, src: BIG_384_29) {.inline.} =
  ## Copy value if big integer ``src`` to ``dst``.
  BIG_384_29_copy(dst, src)

proc shiftr(a: var BIG_384_29, bits: int) {.inline.} =
  ## Shift big integer ``a`` to the right by ``bits`` bits.
  BIG_384_29_shr(a, cint(bits))

proc inf(a: var ECP_BLS381) {.inline.} =
  ## Makes point ``a`` infinite.
  ECP_BLS381_inf(addr a)

proc isinf(a: ECP_BLS381): bool {.inline.} =
  ## Check if ``a`` is infinite.
  var tmp = a
  result = (ECP_BLS381_isinf(addr tmp) != 0)

proc isinf(a: ECP2_BLS381): bool {.inline.} =
  ## Check if ``a`` is infinite.
  var tmp = a
  result = (ECP2_BLS381_isinf(addr tmp) != 0)

proc inf(a: var ECP2_BLS381) {.inline.} =
  ## Makes point ``a`` infinite.
  ECP2_BLS381_inf(addr a)

proc affine(a: var ECP_BLS381) {.inline.} =
  ## Convert ``a`` from (x, y, z) to (x, y).
  ECP_BLS381_affine(addr a)

proc affine(a: var ECP2_BLS381) {.inline.} =
  ## Convert ``a`` from (x, y, z) to (x, y, 1).
  ECP2_BLS381_affine(addr a)

proc add(a: var ECP2_BLS381, b: ECP2_BLS381) {.inline.} =
  ## Add point ``b`` to point ``a``.
  # ECP2_BLS381_add() always return 0.
  discard ECP2_BLS381_add(addr a, unsafeAddr b)

proc add(a: var ECP_BLS381, b: ECP_BLS381) {.inline.} =
  ## Add point ``b`` to point ``a``.
  ECP_BLS381_add(addr a, unsafeAddr b)

proc mul(a: var ECP2_BLS381, b: BIG_384_29) {.inline.} =
  ## Multiply point ``a`` by big integer ``b``.
  ECP2_BLS381_mul(addr a, b)

proc mul(a: var ECP_BLS381, b: BIG_384_29) {.inline.} =
  ## Multiply point ``a`` by big integer ``b``.
  ECP_BLS381_mul(addr a, b)

proc generator2(): ECP2_BLS381 {.inline.} =
  ECP2_BLS381_generator(addr result)

proc `==`(a: FP12_BLS381, b: FP12_BLS381): bool {.inline.} =
  result = (FP12_BLS381_equals(unsafeAddr a, unsafeAddr b) == 1)

proc `$`(a: BIG_384_29): string =
  ## Returns string hexadecimal representation of big integer ``a``.
  result = ""
  var b: BIG_384_29
  var length = bitsCount(a)
  if length mod 4 == 0:
    length = length div 4
  else:
    length = (length div 4) + 1
  if length < MODBYTES_384_29 * 2:
    length = MODBYTES_384_29 * 2
  var i = length - 1
  while i >= 0:
    copy(b, a)
    shiftr(b, i * 4)
    var alpha = b[0] and 0x0F
    if alpha < 10:
      result.add(chr(ord('0') + alpha))
    else:
      result.add(chr(ord('a') - 10 + alpha))
    dec(i)

proc `$`(r: FP_BLS381): string =
  ## Return string representation of ``FP_BLS381``.
  var c: BIG_384_29
  FP_BLS381_redc(c, unsafeAddr r)
  result = $c

proc `$`(w: FP2_BLS381): string =
  ## Return string representation of ``FP2_BLS381``.
  var wx = w
  var bx, by: BIG_384_29
  FP2_BLS381_reduce(addr wx)
  FP_BLS381_redc(bx, addr wx.a)
  FP_BLS381_redc(by, addr wx.b)
  result = "["
  result.add($bx)
  result.add(", ")
  result.add($by)
  result.add("]")

proc `$`(w: FP4_BLS381): string =
  ## Return string representation of ``FP4_BLS381``.
  result = "["
  result.add($w.a)
  result.add(", ")
  result.add($w.b)
  result.add("]")

proc `$`(w: FP12_BLS381): string =
  ## Return string representation of ``FP12_BLS381``.
  result = "["
  result.add($w.a)
  result.add(", ")
  result.add($w.b)
  result.add(", ")
  result.add($w.c)
  result.add("]")

proc `$`(p: ECP_BLS381): string =
  ## Return string representation of ``ECP_BLS381``.
  if p.isinf():
    result = "INFINITY"
  else:
    var x, y: BIG_384_29
    var px = p
    ECP_BLS381_affine(addr px)
    FP_BLS381_redc(x, addr px.x)
    FP_BLS381_redc(y, addr px.y)
    result = "("
    result.add($x)
    result.add(", ")
    result.add($y)
    result.add(")")

proc `$`(p: ECP2_BLS381): string =
  ## Return string representation of ``ECP2_BLS381``.
  if p.isinf():
    result = "INFINITY"
  else:
    var px = p
    var x, y: FP2_BLS381
    discard ECP2_BLS381_get(addr x, addr y, addr px)
    result = "("
    result.add($x)
    result.add(", ")
    result.add($y)
    result.add(")")

proc toBytes(a: BIG_384_29, res: var array[MODBYTES_384_29, byte]) =
  ## Serialize big integer ``a`` to ``res``.
  var c: BIG_384_29
  BIG_384_29_norm(a)
  BIG_384_29_copy(c, a)
  var i = MODBYTES_384_29 - 1
  while i >= 0:
    res[i] = byte(c[0] and 0xFF)
    BIG_384_29_fshr(c, 8)
    dec(i)

proc fromBytes(res: var BIG_384_29, a: openarray[byte]): bool =
  ## Unserialize big integer from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``MODBYTES_384_29``.
  let length = if len(a) > MODBYTES_384_29: MODBYTES_384_29 else: len(a)
  for i in 0..<length:
    discard BIG_384_29_fshl(res, 8)
    res[0] = res[0] + Chunk(a[i])
  result = true

proc toBytes(a: ECP2_BLS381, res: var array[MODBYTES_384_29 * 4, byte]) =
  var aclone = a
  var oct = Octet(max: MODBYTES_384_29 * 4, val: addr res[0])
  ECP2_BLS381_toOctet(addr oct, addr aclone)

proc fromBytes(res: var ECP2_BLS381, a: openarray[byte]): bool =
  if len(a) < MODBYTES_384_29 * 4:
    result = false
  else:
    var oct = Octet(len: MODBYTES_384_29 * 4, max: MODBYTES_384_29 * 4,
                    val: unsafeAddr a[0])
    result = (ECP2_BLS381_fromOctet(addr res, addr oct) == 1)

proc toBytes(a: ECP_BLS381, res: var array[MODBYTES_384_29 * 2 + 1, byte],
              compressed = false) =
  ## Serialize point ``a`` to ``res`` in compressed (if ``compressed ==
  ## true``) or uncompressed (default) form.
  var aclone = a
  var x, y: BIG_384_29

  discard ECP_BLS381_get(x, y, addr aclone)
  if compressed:
    res[0] = 0x02
    if BIG_384_29_parity(y) == 1: res[0] = 0x03
    BIG_384_29_toBytes(cast[ptr char](addr res[1]), x)
  else:
    res[0] = 0x04
    BIG_384_29_toBytes(cast[ptr char](addr res[1]), x)
    BIG_384_29_toBytes(cast[ptr char](addr res[MODBYTES_384_29 + 1]), y)

proc fromBytes(res: var ECP_BLS381, a: openarray[byte]): bool =
  ## Unserialize big integer from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``MODBYTES_384_29 * 2 + 1`` for
  ## uncompressed signature, or at least ``MODBYTES_384_29 + 1`` for
  ## compressed signature.
  var oct: Octet
  let length = len(a)
  if length == MODBYTES_384_29 + 1:
    # Compressed form
    oct = Octet(len: MODBYTES_384_29 + 1,
                max: MODBYTES_384_29 + 1, val: unsafeAddr a[0])
    result = ECP_BLS381_fromOctet(addr res, addr oct) == 1
  elif length == MODBYTES_384_29 * 2 + 1:
    # Uncompressed form
    oct = Octet(len: MODBYTES_384_29 * 2 + 1,
                max: MODBYTES_384_29 * 2 + 1, val: unsafeAddr a[0])
    result = ECP_BLS381_fromOctet(addr res, addr oct) == 1
  else:
    result = false

proc toBytes(a: FP12_BLS381, res: var array[MODBYTES_384_29 * 12, byte]) =
  ## Serialize FP12 ``a`` to ``res``.
  var oct = Octet(max: MODBYTES_384_29 * 12, val: addr res[0])
  FP12_BLS381_toOctet(addr oct, unsafeAddr a)

proc fromBytes(res: var FP12_BLS381, a: openarray[byte]): bool =
  ## Unserialize FP12 from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``MODBYTES_384_29 * 12``.
  if len(a) != MODBYTES_384_29 * 12:
    result = false
  else:
    var oct = Octet(len: MODBYTES_384_29 * 12, max: MODBYTES_384_29 * 12,
                    val: unsafeAddr a[0])
    result = (FP12_BLS381_fromOctet(addr res, addr oct) == 1)

proc mapit(hash: MDigest[384]): GroupG1 =
  ## Map hash value ``hash`` to GroupG1 (ECP)
  var buffer: array[MODBYTES_384_29, byte]
  let pos = MODBYTES_384_29 - len(hash.data)
  copyMem(addr buffer[pos], unsafeAddr hash.data[0], len(hash.data))
  var oct = Octet(len: MODBYTES_384_29, max: MODBYTES_384_29,
                  val: addr buffer[0])
  ECP_BLS381_mapit(addr result, addr oct)

proc atePairing(pointG2: GroupG2, pointG1: GroupG1): FP12_BLS381 =
  ## Pairing `magic` function.
  PAIR_BLS381_ate(addr result, unsafeAddr pointG2, unsafeAddr pointG1)
  PAIR_BLS381_fexp(addr result)

proc random(a: var BIG_384_29) =
  ## Generates random big number `bit by bit` using nimcrypto's sysrand
  ## generator.
  var
    rndb: array[NLEN_384_29, int32]
    rndw: int32
    j: int32
    k: int32

  doAssert(randomBytes(rndb) == NLEN_384_29)
  let length = 8 * MODBYTES_384_29
  a.zero()
  for i in 0..<length:
    if j == 0:
      rndw = rndb[k]
      inc(k)
    else:
      rndw = rndw shr 1
    let b = rndw and 1
    BIG_384_29_shl(a, 1)
    a[0] = a[0] + b
    inc(j)
    j = j and 0x1F

proc randomNum(a: var BIG_384_29, q: BIG_384_29) =
  ## Generates random big number `bit by bit` over modulo ``q`` using
  ## nimcrypto's sysrand generator.
  var
    d: DBIG_384_29
    rndb: array[DNLEN_384_29, int32]
    rndw: int32
    j: int32
    k: int32

  doAssert(randomBytes(rndb) == DNLEN_384_29)
  let length = 2 * BIG_384_29_nbits(q)
  a.zero()

  for i in 0..<length:
    if j == 0:
      rndw = rndb[k]
      inc(k)
    else:
      rndw = rndw shr 1
    let b = rndw and 1
    BIG_384_29_dshl(d, 1)
    d[0] = d[0] + b
    inc(j)
    j = j and 0x1F
  BIG_384_29_dmod(a, d, q)

proc `$`*(sigkey: SigKey): string {.inline.} =
  ## Return string representation of Signature (Private) key.
  result = $sigkey.x

proc `$`*(verkey: VerKey | AggregatedVerKey): string {.inline.} =
  ## Return string representation of Verification (Public) key.
  var buf: array[MODBYTES_384_29 * 4, byte]
  toBytes(verkey.point, buf)
  result = toHex(buf, true)

proc `$`*(sig: Signature | AggregatedSignature): string {.inline.} =
  ## Return string representation of ``uncompressed`` signature.
  var buf: array[MODBYTES_384_29 * 2 + 1, byte]
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
                              allkeys: openarray[VerKey]): BIG_384_29 =

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

# Due to BLS proof of possession in the beacon chain we don't need
# to sort the keys to avoid rogue key attacks
# proc initAggregatedSignature*(sk: openarray[SigPair]): AggregatedSignature =
#   ## Create Aggregated Signature from array of signature and verification keys
#   ## pairs.
#   var sortsk = sorted(sk, cmp)
#   var keys = newSeq[VerKey]()
#   var sigs = newSeq[Signature]()

#   for item in sortsk:
#     keys.add(item.key)

#   result.point.inf()
#   for item in sortsk:
#     var hh = blake2_384.hashVerkeyForAggregation(item.key, keys)
#     var sig = item.sig
#     sig.point.mul(hh)
#     result.point.add(sig.point)
#     result.point.affine()

proc initAggregatedSignature*(
    pubkeys_sigs: tuple[
      pkeys: seq[VerKey],
      signatures: seq[Signature]
    ]): AggregatedSignature =
  ## Create Aggregated Signature from 2 arrays of signatures and
  ## verification keys.
  ## Important: This requires a proof of possession
  ## No sorting is done to prevent rogue key attacks
  # TODO: use a tuple of openarrays instead

  # Aliases
  template pubkeys(): seq[VerKey] =
    pubkeys_sigs.pkeys
  template sigs(): seq[Signature] =
    pubkeys_sigs.signatures

  doAssert pubkeys.len == sigs.len

  result.point.inf()
  for i in 0 ..< pubkeys.len:
    var hh = blake2_384.hashVerkeyForAggregation(pubkeys[i], pubkeys)
    var sig = sigs[i]
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
