# Milagro Crypto
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import nimcrypto/[sysrand, utils, hash]
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

const
  RawSignatureKeySize* = MODBYTES_384_29
  RawVerificationKeySize* = MODBYTES_384_29 * 4
  RawSignatureSize* = MODBYTES_384_29 * 2 + 1

proc zero*(a: var BIG_384_29) {.inline.} =
  ## Make big integer ``a`` be zero.
  for i in 0..<len(a):
    a[i] = 0

proc bitsCount*(a: BIG_384_29): int {.inline.} =
  ## Returns number of bits in big integer ``a``.
  result = BIG_384_29_nbits(a)

proc copy*(dst: var BIG_384_29, src: BIG_384_29) {.inline.} =
  ## Copy value if big integer ``src`` to ``dst``.
  BIG_384_29_copy(dst, src)

proc shiftr*(a: var BIG_384_29, bits: int) {.inline.} =
  ## Shift big integer ``a`` to the right by ``bits`` bits.
  BIG_384_29_shr(a, bits)

proc inf*(a: var ECP_BLS381) {.inline.} =
  ## Makes point ``a`` infinite.
  ECP_BLS381_inf(addr a)

proc `$`*(a: BIG_384_29): string =
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

proc toBytes*(a: BIG_384_29, res: var array[MODBYTES_384_29, byte]) =
  ## Serialize big integer ``a`` to ``res``.  
  var c: BIG_384_29
  BIG_384_29_norm(a)
  BIG_384_29_copy(c, a)
  var i = MODBYTES_384_29 - 1
  while i >= 0:
    res[i] = byte(c[0] and 0xFF)
    BIG_384_29_fshr(c, 8)
    dec(i)

proc fromBytes*(a: openarray[byte], res: var BIG_384_29): bool =
  ## Unserialize big integer from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``MODBYTES_384_29``.
  let length = if len(a) > MODBYTES_384_29: MODBYTES_384_29 else: len(a)
  for i in 0..<length:
    BIG_384_29_fshl(res, 8)
    res[0] = res[0] + Chunk(a[i])
  result = true

proc toBytes*(a: ECP2_BLS381, res: var array[MODBYTES_384_29 * 4, byte]) =
  var oct = Octet(max: MODBYTES_384_29 * 4, val: addr res[0])
  ECP2_BLS381_toOctet(addr oct, unsafeAddr a)

proc fromBytes*(a: openarray[byte], res: var ECP2_BLS381): bool =
  if len(a) != MODBYTES_384_29 * 4:
    result = false
  else:
    var oct = Octet(len: MODBYTES_384_29 * 4, max: MODBYTES_384_29 * 4,
                    val: unsafeAddr a[0])
    ECP2_BLS381_fromOctet(addr res, addr oct)

proc toBytesCompress*(a: ECP_BLS381,
                      res: var array[MODBYTES_384_29 + 1, byte]) =
  ## Serialize point ``a`` to ``res`` in compressed form.
  var oct = Octet(max: MODBYTES_384_29 + 1, val: addr res[0])
  ECP_BLS381_toOctet(addr oct, unsafeAddr a, true)

proc toBytes*(a: ECP_BLS381, res: var array[MODBYTES_384_29 * 2 + 1, byte]) =
  ## Serialize point ``a`` to ``res`` in uncompressed form.
  var oct = Octet(max: MODBYTES_384_29 * 2 + 1, val: addr res[0])
  ECP_BLS381_toOctet(addr oct, unsafeAddr a, false)

proc fromBytes*(a: openarray[byte], res: var ECP_BLS381): bool =
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

proc toBytes*(a: FP12_BLS381, res: var array[MODBYTES_384_29 * 12, byte]) =
  ## Serialize FP12 ``a`` to ``res``.
  var oct = Octet(max: MODBYTES_384_29 * 12, val: addr res[0])
  FP12_BLS381_toOctet(addr oct, unsafeAddr a)

proc fromBytes*(a: openarray[byte], res: var FP12_BLS381): bool =
  ## Unserialize FP12 from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``MODBYTES_384_29 * 12``.
  if len(a) != MODBYTES_384_29 * 12:
    result = false
  else:
    var oct = Octet(len: MODBYTES_384_29 * 12, max: MODBYTES_384_29 * 12,
                    val: unsafeAddr a[0])
    result = (FP12_BLS381_fromOctet(addr res, addr oct) == 1)

proc mapit*(hash: MDigest[256]): GroupG1 =
  ## Map hash value ``hash`` to GroupG1 (ECP)
  var oct = Octet(len: 32, max: 32, val: unsafeAddr hash.data[0])
  ECP_BLS381_mapit(addr result, addr oct)

proc atePairing*(pointG2: GroupG2, pointG1: GroupG1): FP12_BLS381 =
  PAIR_BLS381_ate(addr result, unsafeAddr pointG2, unsafeAddr pointG1)
  PAIR_BLS381_fexp(addr result)

proc random*(a: var BIG_384_29) =
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

proc randomNum*(a: var BIG_384_29, q: BIG_384_29) =
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

proc `$`*(verkey: VerKey): string {.inline.} =
  ## Return string representation of Verification (Public) key.
  var buf: array[MODBYTES_384_29 * 4, byte]
  toBytes(verkey.point, buf)
  result = toHex(buf, true)

proc `$`*(sig: Signature): string {.inline.} =
  ## Return string representation of ``uncompressed`` signature.
  var buf: array[MODBYTES_384_29 * 2 + 1, byte]
  toBytes(sig.point, buf)
  result = toHex(buf, true)

proc newSigKey*(): SigKey =
  ## Creates new random Signature (Private) key.
  random(result.x)

proc fromSigKey*(a: SigKey): VerKey =
  ## Create new Verification (Public) key from Signature (Private) key.
  var gen: ECP2_BLS381
  ECP2_BLS381_generator(addr gen)
  ECP2_BLS381_mul(addr gen, a.x)
  result.point = gen

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
  if not fromBytes(data, result.x):
    raise newException(ValueError, "Error in signature key conversion")

proc initSigKey*(data: string): SigKey =
  ## Initialize Signature key from serialized hexadecimal string ``data``.
  result = initSigKey(fromHex(data))

proc initVerKey*(data: openarray[byte]): VerKey =
  ## Initialize Verification key from serialized form ``data``.
  if not fromBytes(data, result.point):
    raise newException(ValueError, "Error in verification key conversion")

proc initVerKey*(data: string): VerKey =
  ## Initialize Verification key from serialized hexadecimal string ``data``.
  result = initVerKey(fromHex(data))

proc initSignature*(data: openarray[byte]): Signature =
  ## Initialize Signature from serialized form ``data``.
  if not fromBytes(data, result.point):
    raise newException(ValueError, "Error in signature conversion")

proc initSignature*(data: string): Signature =
  ## Initialize Signature from serialized hexadecimal string ``data``.
  result = initSignature(fromHex(data))

proc newKeyPair*(): KeyPair =
  ## Create new random pair of Signature (Private) and Verification (Public)
  ## keys.
  result.sigkey = newSigKey()
  result.verkey = fromSigKey(result.sigkey)

proc signMessage*(sigkey: SigKey, hash: MDigest[256]): Signature =
  ## Sign 256-bit ``hash`` using Signature (Private) key ``sigkey``.
  var point = hash.mapit()
  ECP_BLS381_mul(addr point, sigkey.x)
  result.point = point

proc verifyMessage*(sig: Signature, hash: MDigest[256], verkey: VerKey): bool =
  ## Verify 256-bit ``hash`` and signature ``sig`` using Verification (Public)
  ## key ``verkey``. Returns ``true`` if verification succeeded.
  if ECP_BLS381_isinf(unsafeAddr sig.point) == 1:
    result = false
  else:
    var gen: ECP2_BLS381
    var point = hash.mapit()
    ECP2_BLS381_generator(addr gen)
    var lhs = atePairing(gen, sig.point)
    var rhs = atePairing(verkey.point, point)
    result = (FP12_BLS381_equals(addr lhs, addr rhs) == 1)
