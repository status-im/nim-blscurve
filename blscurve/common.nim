# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.
import endians
import nimcrypto/[sysrand, utils, hash, keccak]
import milagro

{.deadCodeElim: on.}

var CURVE_Order* {.importc: "CURVE_Order_BLS381".}: BIG_384
var FIELD_Modulus* {.importc: "Modulus_BLS381".}: BIG_384

const
  AteBitsCount* = 65 ## ATE_BITS_BLS381 value

when sizeof(int) == 4 or defined(use32):
  const
    G2_CoFactorHigh*: BIG_384 = [
      0x1A6691AE'i32, 0x0A9BF149'i32, 0x07A0BBC8'i32, 0x11E3969B'i32,
      0x07DDFA62'i32, 0x102D972D'i32, 0x0AEA9A28'i32, 0x08A8E10B'i32,
      0x02CD91DE'i32, 0x0943B510'i32, 0x0247541E'i32, 0x0829CFE2'i32,
      0x1D543A95'i32, 0x00000002'i32
    ]
    G2_CoFactorLow*: BIG_384 = [
      0x1C7238E5'i32, 0x18E1C718'i32, 0x1BC31C33'i32, 0x0DD8DCF0'i32,
      0x00000161'i32, 0x00000000'i32, 0x00000000'i32, 0x00000000'i32,
      0x00000000'i32, 0x00000000'i32, 0x00000000'i32, 0x00000000'i32,
      0x00000000'i32, 0x00000000'i32
    ]
    G2_CoFactorShift*: BIG_384 = [
      0x00000000'i32, 0x00000000'i32, 0x00000000'i32, 0x00000000'i32,
      0x00001000'i32, 0x00000000'i32, 0x00000000'i32, 0x00000000'i32,
      0x00000000'i32, 0x00000000'i32, 0x00000000'i32, 0x00000000'i32,
      0x00000000'i32, 0x00000000'i32
    ]
elif sizeof(int) == 8:
  const
    G2_CoFactorHigh*: BIG_384 = [
      0x01537E293A6691AE'i64, 0x023C72D367A0BBC8'i64, 0x0205B2E5A7DDFA62'i64,
      0x01151C216AEA9A28'i64, 0x012876A202CD91DE'i64, 0x010539FC4247541E'i64,
      0x000000005D543A95'i64
    ]
    G2_CoFactorLow*: BIG_384 = [
      0x031C38E31C7238E5'i64, 0x01BB1B9E1BC31C33'i64, 0x0000000000000161'i64,
      0x0000000000000000'i64, 0x0000000000000000'i64, 0x0000000000000000'i64,
      0x0000000000000000'i64
    ]
    G2_CoFactorShift*: BIG_384 = [
      0x0000000000000000'i64, 0x0000000000000000'i64, 0x0000000000001000'i64,
      0x0000000000000000'i64, 0x0000000000000000'i64, 0x0000000000000000'i64,
      0x0000000000000000'i64
    ]

proc zero*(a: var BIG_384) {.inline.} =
  ## Make big integer ``a`` be zero.
  for i in 0..<len(a):
    a[i] = 0

proc bitsCount*(a: BIG_384): int {.inline.} =
  ## Returns number of bits in big integer ``a``.
  result = BIG_384_nbits(a)

proc copy*(dst: var BIG_384, src: BIG_384) {.inline.} =
  ## Copy value if big integer ``src`` to ``dst``.
  BIG_384_copy(dst, src)

proc setOne*(dst: var FP2_BLS381) {.inline.} =
  ## Set value of ``dst`` to FP2.one
  FP2_BLS381_one(addr dst)

proc add*(dst: var FP2_BLS381, x: FP2_BLS381, y: FP2_BLS381) {.inline.} =
  ## Set ``dst`` to ``x + y``.
  FP2_BLS381_add(addr dst, unsafeAddr x, unsafeAddr y)

proc add*(x: FP2_BLS381, y: FP2_BLS381): FP2_BLS381 {.inline.} =
  ## Returns ``x + y``.
  FP2_BLS381_add(addr result, unsafeAddr x, unsafeAddr y)

proc shiftr*(a: var BIG_384, bits: int) {.inline.} =
  ## Shift big integer ``a`` to the right by ``bits`` bits.
  BIG_384_shr(a, cint(bits))

proc norm*(a: BIG_384) {.inline.} =
  ## Normalize big integer value.
  ## All digits of the input are reduced ``mod 2^BASEBITS``.
  discard BIG_384_norm(a)

proc norm*(a: var FP_BLS381) {.inline.} =
  ## Normalize FP field member.
  FP_BLS381_norm(addr a)

proc norm*(a: var FP2_BLS381) {.inline.} =
  ## Normalize FP2 field number.
  FP2_BLS381_norm(addr a)

proc sqr*(x: FP2_BLS381): FP2_BLS381 {.inline.} =
  ## Retruns ``x ^ 2``.
  FP2_BLS381_sqr(addr result, unsafeAddr x)

proc nres*(a: BIG_384): FP_BLS381 {.inline.} =
  ## Convert big integer value to residue form mod Modulus.
  FP_BLS381_nres(addr result, a)

proc cmp*(a: BIG_384, b: BIG_384): int {.inline.} =
  ## Compares two big integers, inputs must be normalized externally
  ##
  ## Returns ``-1`` if ``a < b``, ``0`` if ``a == b``, ``1`` if ``a > b``
  result = int(BIG_384_comp(a, b))

proc cmp*(a: FP_BLS381, b: FP_BLS381): int {.inline.} =
  ## Compares two FP field members
  ##
  ## Returns ``-1`` if ``a < b``, ``0`` if ``a == b``, ``1`` if ``a > b``
  var ab, bb: BIG_384
  FP_BLS381_redc(ab, unsafeAddr a)
  FP_BLS381_redc(bb, unsafeAddr b)
  result = cmp(ab, bb)

proc cmp*(a: FP2_BLS381, b: FP2_BLS381): int {.inline.} =
  ## Compares two FP2 field members.
  ##
  ## Returns ``-1`` if ``a < b``, ``0`` if ``a == b``, ``1`` if ``a > b``
  result = cmp(a.b, b.b)
  if result == 0:
    result = cmp(a.a, b.a)

proc neg*(a: FP_BLS381): FP_BLS381 {.inline.} =
  ## Return negated copy of ``a``. ``result = -a``.
  result = a
  FP_BLS381_neg(addr result, unsafeAddr a)

proc neg*(a: FP2_BLS381): FP2_BLS381 {.inline.} =
  ## Return negated copy of ``a``. ``result = -a``.
  result = a
  FP2_BLS381_neg(addr result, unsafeAddr a)

proc neg*(a: ECP2_BLS381): ECP2_BLS381 {.inline.} =
  ## Negates point ``a``. On exit a = -a.
  result = a
  ECP2_BLS381_neg(addr result)

proc neg*(a: ECP_BLS381): ECP_BLS381 {.inline.} =
  ## Negates point ``a``. On exit a = -a.
  result = a
  ECP_BLS381_neg(addr result)

proc inf*(a: var ECP_BLS381) {.inline.} =
  ## Makes point ``a`` infinite.
  ECP_BLS381_inf(addr a)

proc isinf*(a: ECP_BLS381): bool {.inline.} =
  ## Check if ``a`` is infinite.
  var tmp = a
  result = (ECP_BLS381_isinf(addr tmp) != 0)

proc isinf*(a: ECP2_BLS381): bool {.inline.} =
  ## Check if ``a`` is infinite.
  var tmp = a
  result = (ECP2_BLS381_isinf(addr tmp) != 0)

proc rhs*(x: FP2_BLS381): FP2_BLS381 {.inline.} =
  ## Returns ``x ^ 3 + b``.
  ECP2_BLS381_rhs(addr result, unsafeAddr x)

proc iszilch*(a: FP2_BLS381): bool {.inline.} =
  ## Returns ``true`` if ``a`` is zero.
  result = (FP2_BLS381_iszilch(unsafeAddr a) == 1)

proc parity*(a: FP2_BLS381): int {.inline.} =
  ## Returns parity for ``a``.
  var t: BIG_384
  FP_BLS381_redc(t, unsafeAddr a.a)
  result = int(BIG_384_parity(t))

proc parity*(a: FP_BLS381): int {.inline.} =
  ## Returns parity for ``a``.
  var t: BIG_384
  FP_BLS381_redc(t, unsafeAddr a)
  result = int(BIG_384_parity(t))

proc parity*(a: BIG_384): int {.inline.} =
  ## Returns parity for ``a``.
  result = int(BIG_384_parity(a))

proc inf*(a: var ECP2_BLS381) {.inline.} =
  ## Makes point ``a`` infinite.
  ECP2_BLS381_inf(addr a)

proc affine*(a: var ECP_BLS381) {.inline.} =
  ## Convert ``a`` from (x, y, z) to (x, y).
  ECP_BLS381_affine(addr a)

proc affine*(a: var ECP2_BLS381) {.inline.} =
  ## Convert ``a`` from (x, y, z) to (x, y, 1).
  ECP2_BLS381_affine(addr a)

proc add*(a: var ECP2_BLS381, b: ECP2_BLS381) {.inline.} =
  ## Add point ``b`` to point ``a``.
  # ECP2_BLS381_add() always return 0.
  discard ECP2_BLS381_add(addr a, unsafeAddr b)

proc double*(a: var ECP2_BLS381) {.inline.} =
  ## Doubles point ``a``.
  discard ECP2_BLS381_dbl(addr a)

proc add*(a: var ECP_BLS381, b: ECP_BLS381) {.inline.} =
  ## Add point ``b`` to point ``a``.
  ECP_BLS381_add(addr a, unsafeAddr b)

proc mul*(a: var ECP2_BLS381, b: BIG_384) {.inline.} =
  ## Multiply point ``a`` by big integer ``b``.
  ECP2_BLS381_mul(addr a, b)

proc mul*(a: var ECP_BLS381, b: BIG_384) {.inline.} =
  ## Multiply point ``a`` by big integer ``b``.
  ECP_BLS381_mul(addr a, b)

proc get*(a: ECP2_BLS381, x, y: var FP2_BLS381): int {.inline.} =
  ## Get coordinates ``x`` and ``y`` from point ``a``.
  result = int(ECP2_BLS381_get(addr x, addr y, unsafeAddr a))

proc get*(a: ECP_BLS381, x, y: var BIG_384): int {.inline.} =
  ## Get coordinates ``x`` and ``y`` from point ``a``.
  result = int(ECP_BLS381_get(x, y, unsafeAddr a))

proc `==`*(a, b: ECP_BLS381): bool {.inline.} =
  ## Compare points ``a`` and ``b`` in ECP Group.
  result = (ECP_BLS381_equals(unsafeAddr a, unsafeAddr b) == 1)

proc `==`*(a, b: ECP2_BLS381): bool {.inline.} =
  ## Compare points ``a`` and ``b`` in ECP2 Group.
  result = (ECP2_BLS381_equals(unsafeAddr a, unsafeAddr b) == 1)

proc `==`*(a, b: FP_BLS381): bool {.inline.} =
  ## Compare field elements over FP.
  result = (FP_BLS381_equals(unsafeAddr a, unsafeAddr b) == 1)

proc `==`*(a, b: FP2_BLS381): bool {.inline.} =
  ## Compare field elements over FP2.
  result = (FP2_BLS381_equals(unsafeAddr a, unsafeAddr b) == 1)

proc `==`*(a, b: FP12_BLS381): bool {.inline.} =
  ## Compare field elements over FP12.
  result = (FP12_BLS381_equals(unsafeAddr a, unsafeAddr b) == 1)

proc `$`*(a: BIG_384): string =
  ## Returns string hexadecimal representation of big integer ``a``.
  result = ""
  var b: BIG_384
  var length = bitsCount(a)
  if length mod 4 == 0:
    length = length div 4
  else:
    length = (length div 4) + 1
  if length < MODBYTES_384 * 2:
    length = MODBYTES_384 * 2
  for i in countdown(length - 1, 0):
    b.copy(a)
    b.shiftr(i * 4)
    var alpha = b[0] and 0x0F
    if alpha < 10:
      result.add(chr(ord('0') + alpha))
    else:
      result.add(chr(ord('a') - 10 + alpha))

proc `$`*(r: FP_BLS381): string =
  ## Return string representation of ``FP_BLS381``.
  var c: BIG_384
  FP_BLS381_redc(c, unsafeAddr r)
  result = $c

proc `$`*(w: FP2_BLS381): string =
  ## Return string representation of ``FP2_BLS381``.
  var wx = w
  var bx, by: BIG_384
  FP2_BLS381_reduce(addr wx)
  FP_BLS381_redc(bx, addr wx.a)
  FP_BLS381_redc(by, addr wx.b)
  result = "["
  result.add($bx)
  result.add(", ")
  result.add($by)
  result.add("]")

proc `$`*(w: FP4_BLS381): string =
  ## Return string representation of ``FP4_BLS381``.
  result = "["
  result.add($w.a)
  result.add(", ")
  result.add($w.b)
  result.add("]")

proc `$`*(w: FP12_BLS381): string =
  ## Return string representation of ``FP12_BLS381``.
  result = "["
  result.add($w.a)
  result.add(", ")
  result.add($w.b)
  result.add(", ")
  result.add($w.c)
  result.add("]")

proc `$`*(p: ECP_BLS381): string =
  ## Return string representation of ``ECP_BLS381``.
  if p.isinf():
    result = "INFINITY"
  else:
    var x, y: BIG_384
    var px = p
    ECP_BLS381_affine(addr px)
    FP_BLS381_redc(x, addr px.x)
    FP_BLS381_redc(y, addr px.y)
    result = "("
    result.add($x)
    result.add(", ")
    result.add($y)
    result.add(")")

proc `$`*(p: ECP2_BLS381): string =
  ## Return string representation of ``ECP2_BLS381``.
  if p.isinf():
    result = "INFINITY"
  else:
    result = "("
    result.add($p.x)
    result.add(", ")
    result.add($p.y)
    result.add(", ")
    result.add($p.z)
    result.add(")")

proc setx*(p: var ECP2_BLS381, x: FP2_BLS381, greatest: bool): int =
  ## Set value of ``p`` using just ``x`` coord with care to ``greatest``.
  ##
  ## This is custom `setx` procedure which works in way compatible to
  ## rust's library https://github.com/zkcrypto/pairing.
  var y, negy: FP2_BLS381
  ECP2_BLS381_rhs(addr y, unsafeAddr x)
  if FP2_BLS381_sqrt(addr y, addr y) != 1:
    ECP2_BLS381_inf(addr p)
    result = 0
  else:
    FP2_BLS381_copy(addr p.x, unsafeAddr x)
    FP2_BLS381_copy(addr negy, addr y)
    FP2_BLS381_neg(addr negy, addr negy)
    if not((cmp(y, negy) < 0) xor greatest):
      FP2_BLS381_copy(addr p.y, addr negy)
    else:
      FP2_BLS381_copy(addr p.y, addr y)
    FP2_BLS381_one(addr p.z)
    result = 1

proc setx*(p: var ECP2_BLS381, x: FP2_BLS381, parity: int): int =
  ## Set value of ``p`` using just ``x`` coord with care to ``greatest``.
  ##
  ## This is custom `setx` procedure which works in way compatible to
  ## python's version.
  var y, negy: FP2_BLS381
  var tmp0, tmp1: ECP2_BLS381
  ECP2_BLS381_rhs(addr y, unsafeAddr x)
  if FP2_BLS381_sqrt(addr y, addr y) != 1:
    ECP2_BLS381_inf(addr p)
    result = 0
  else:
    FP2_BLS381_copy(addr p.x, unsafeAddr x)
    FP2_BLS381_copy(addr negy, addr y)
    FP2_BLS381_neg(addr negy, addr negy)
    if parity(y) != parity:
      FP2_BLS381_copy(addr p.y, addr negy)
    else:
      FP2_BLS381_copy(addr p.y, addr y)
    FP2_BLS381_one(addr p.z)
    result = 1

proc setx*(p: var ECP_BLS381, x: BIG_384, greatest: bool): int =
  ## Set value of ``p`` using just ``x`` coord with care to ``greatest``.
  ##
  ## This is custom `setx` procedure which works in way compatible to
  ## rust's library https://github.com/zkcrypto/pairing.
  var rhs, negy: FP_BLS381
  var t, m: BIG_384
  BIG_384_rcopy(m, FIELD_Modulus)
  FP_BLS381_nres(addr rhs, x)
  ECP_BLS381_rhs(addr rhs, addr rhs)
  FP_BLS381_redc(t, addr rhs)
  if BIG_384_jacobi(t, m) != 1:
    p.inf()
    result = 0
  else:
    FP_BLS381_nres(addr p.x, x)
    FP_BLS381_sqrt(addr p.y, addr rhs)
    FP_BLS381_redc(t, addr p.y)
    FP_BLS381_neg(addr negy, addr p.y)
    FP_BLS381_norm(addr negy)
    if not((cmp(p.y, negy) < 0) xor greatest):
      p.y = negy
    FP_BLS381_reduce(addr p.y)
    FP_BLS381_one(addr p.z)
    result = 1

proc setx*(p: var ECP_BLS381, x: BIG_384, parity: int): int =
  ## Set value of ``p`` using just ``x`` coord with care to ``parity``.
  ##
  ## This is custom `setx` procedure which works in way compatible to
  ## python's version.
  var rhs, negy: FP_BLS381
  var t, m: BIG_384
  BIG_384_rcopy(m, FIELD_Modulus)
  FP_BLS381_nres(addr rhs, x)
  ECP_BLS381_rhs(addr rhs, addr rhs)
  FP_BLS381_redc(t, addr rhs)
  if BIG_384_jacobi(t, m) != 1:
    p.inf()
    result = 0
  else:
    FP_BLS381_nres(addr p.x, x)
    FP_BLS381_sqrt(addr p.y, addr rhs)
    FP_BLS381_redc(t, addr p.y)
    FP_BLS381_neg(addr negy, addr p.y)
    FP_BLS381_norm(addr negy)
    if parity(t) != parity:
      p.y = negy
    FP_BLS381_reduce(addr p.y)
    FP_BLS381_one(addr p.z)
    result = 1

proc fromBigs*(p: var FP2_BLS381, x, y: BIG_384) {.inline.} =
  ## Set value of ``p`` from two big integers ``x`` and ``y``.
  FP2_BLS381_from_BIGs(addr p, x, y)

proc fromBigs*(p: var ECP2_BLS381, xr, xi, yr, yi, zr, zi: BIG_384) =
  ## Set value of ``p`` from 6 big integers.
  var x, y, z: FP2_BLS381
  x.fromBigs(xr, xi)
  y.fromBigs(yr, yi)
  z.fromBigs(zr, zi)
  p.x = x
  p.y = y
  p.z = z

proc fromFPs*(p: var FP2_BLS381, x, y: FP_BLS381) {.inline.} =
  ## Set value of ``p`` from two big integers ``x`` and ``y``.
  FP2_BLS381_from_FPs(addr p, x, y)

proc generator1*(): ECP_BLS381 {.inline.} =
  ECP_BLS381_generator(addr result)

proc generator2*(): ECP2_BLS381 {.inline.} =
  ECP2_BLS381_generator(addr result)

proc isOnCurve*(x: FP2_BLS381, y: FP2_BLS381): bool =
  ## Returns ``true`` if point is on curve or points to infinite.
  if x.iszilch() and y.iszilch():
    result = true
  else:
    result = (sqr(y) == rhs(x))

proc toBytes*(a: BIG_384, res: var openarray[byte]): bool =
  ## Serialize big integer ``a`` to ``res``. Length of ``res`` array
  ## must be at least ``MODBYTES_384``.
  ##
  ## Returns ``true`` if ``a`` was succesfully serialized,
  ## ``false`` otherwise.
  if len(res) >= MODBYTES_384:
    var c: BIG_384
    BIG_384_copy(c, a)
    # BIG_384_norm() function in Milagro operates inplace.
    discard BIG_384_norm(c)
    for i in countdown(MODBYTES_384 - 1, 0):
      res[i] = byte(c[0] and 0xFF)
      BIG_384_fshr(c, 8)
    result = true

proc toHex*(a: BIG_384): string {.inline.} =
  ## Serialize big integer ``a`` and return hexadecimal string
  ## representation, if serialization failed empty string will be returned.
  var buffer: array[MODBYTES_384, byte]
  if toBytes(a, buffer):
    result = toHex(buffer)

proc getBytes*(a: BIG_384): array[MODBYTES_384, byte] =
  ## Serialize big integer ``a`` and return array of bytes.
  discard toBytes(a, result)

proc fromBytes*(res: var BIG_384, a: openarray[byte]): bool =
  ## Unserialize big integer from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``MODBYTES_384_29``.
  let length = if len(a) > MODBYTES_384: MODBYTES_384 else: len(a)
  for i in 0..<length:
    discard BIG_384_fshl(res, 8)
    res[0] = res[0] + cast[Chunk](a[i])
  result = true

proc fromHex*(res: var BIG_384, a: string): bool {.inline.} =
  ## Unserialize big integer from hexadecimal string ``a`` to ``res``.
  ##
  ## Returns ``true`` if conversion was successfull.
  fromBytes(res, fromHex(a))

proc toBytes*(point: ECP2_BLS381, res: var openarray[byte]): bool =
  ## Serialize ECP2(G2) point ``point`` to ``res``. Length of ``res`` array
  ## must be at least ``MODBYTES_384 * 2``.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  ##
  ## Returns ``true`` if ``a`` was succesfully serialized,
  ## ``false`` otherwise.
  if len(res) >= MODBYTES_384 * 2:
    var x, y: FP2_BLS381
    var x0, x1, y0: BIG_384
    if point.get(x, y) == -1:
      zeroMem(addr res[0], MODBYTES_384 * 2)
      result = true
    else:
      FP_BLS381_redc(x0, addr x.a)
      FP_BLS381_redc(x1, addr x.b)
      FP_BLS381_redc(y0, addr y.a)
      var parity = int(BIG_384_parity(y0))
      discard toBytes(x0, res.toOpenArray(0, MODBYTES_384 - 1))
      discard toBytes(x1, res.toOpenArray(MODBYTES_384, MODBYTES_384 * 2 - 1))
      if parity == 1:
        res[0] = res[0] or (1'u8 shl 7)
      result = true

proc toHex*(point: ECP2_BLS381): string =
  ## Serialize ECP2(G2) point ``point`` and return hexadecimal string
  ## representation, if serialization failed empty string will be returned.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  var buffer: array[MODBYTES_384 * 2, byte]
  if toBytes(point, buffer):
    result = toHex(buffer)

proc getBytes*(point: ECP2_BLS381): array[MODBYTES_384 * 2, byte] =
  ## Serialize ECP2(G2) point ``point`` and return array of bytes.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  discard toBytes(point, result)

proc fromBytes*(res: var ECP2_BLS381, data: openarray[byte]): bool =
  ## Unserialize ECP2(G2) point from array of bytes ``data``.
  ##
  ## This procedure supports only compressed form of serialization.
  ##
  ## Returns ``true`` on success, ``false`` otherwise.
  if len(data) >= MODBYTES_384 * 2:
    if isFullZero(data.toOpenArray(0, MODBYTES_384 * 2 - 1)):
      res.inf()
      result = true
    else:
      var x0, x1: BIG_384
      var buffer: array[MODBYTES_384, byte]
      copyMem(addr buffer[0], unsafeAddr data[0], MODBYTES_384)
      var parity = int((buffer[0] shr 7) and 1'u8)
      buffer[0] = buffer[0] and 0x3F'u8
      if x0.fromBytes(buffer):
        if x1.fromBytes(data.toOpenArray(MODBYTES_384, MODBYTES_384 * 2 - 1)):
          var x: FP2_BLS381
          x.fromBigs(x0, x1)
          if res.setx(x, parity) == 1:
            result = true

proc fromHex*(res: var ECP2_BLS381, a: string): bool {.inline.} =
  ## Unserialize ECP2(G2) point from hexadecimal string ``a`` to ``res``.
  ##
  ## This procedure supports only compressed form of serialization.
  ##
  ## Returns ``true`` if conversion was successfull.
  fromBytes(res, fromHex(a))

proc toBytes*(point: ECP_BLS381, res: var openarray[byte]): bool =
  ## Serialize ECP(G1) point ``point`` to ``res``. Length of ``res`` array
  ## must be at least ``MODBYTES_384``.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  ##
  ## Returns ``true`` if ``a`` was succesfully serialized,
  ## ``false`` otherwise.
  if len(res) >= MODBYTES_384:
    var x, y: BIG_384
    let parity = point.get(x, y)
    if parity == -1:
      zeroMem(addr res[0], MODBYTES_384)
      result = true
    else:
      discard toBytes(x, res.toOpenArray(0, MODBYTES_384 - 1))
      if parity == 1:
        res[0] = res[0] or (1'u8 shl 7)
      result = true

proc toHex*(point: ECP_BLS381): string =
  ## Serialize ECP(G1) point ``point`` and return hexadecimal string
  ## representation, if serialization failed empty string will be returned.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  var buffer: array[MODBYTES_384, byte]
  if toBytes(point, buffer):
    result = toHex(buffer)

proc getBytes*(point: ECP_BLS381): array[MODBYTES_384, byte] =
  ## Serialize ECP(G1) point ``point`` and return array of bytes.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  discard toBytes(point, result)

proc fromBytes*(res: var ECP_BLS381, data: openarray[byte]): bool =
  ## Unserialize ECP point from array of bytes ``data``.
  ##
  ## This procedure supports only compressed form of serialization.
  ##
  ## Returns ``true`` on success, ``false`` otherwise.
  if len(data) >= MODBYTES_384:
    if isFullZero(data.toOpenArray(0, MODBYTES_384 - 1)):
      res.inf()
      result = true
    else:
      var x: BIG_384
      var buffer: array[MODBYTES_384, byte]
      copyMem(addr buffer[0], unsafeAddr data[0], MODBYTES_384)
      var parity = int((buffer[0] shr 7) and 1'u8)
      buffer[0] = buffer[0] and 0x3F'u8
      if x.fromBytes(buffer):
        if res.setx(x, parity) == 1:
          result = true

proc fromHex*(res: var ECP_BLS381, a: string): bool {.inline.} =
  ## Unserialize ECP point from hexadecimal string ``a`` to ``res``.
  ##
  ## This procedure supports only compressed form of serialization.
  ##
  ## Returns ``true`` if conversion was successfull.
  fromBytes(res, fromHex(a))

proc mulCoFactor*(point: ECP2_BLS381): ECP2_BLS381 =
  ## Multiplies ECP2(G2) point by a cofactor of G2.
  var lowpart: ECP2_BLS381
  result = point
  lowpart = point
  mul(result, G2_CoFactorHigh)
  mul(result, G2_CoFactorShift)
  mul(lowpart, G2_CoFactorLow)
  add(result, lowpart)

proc hashToG2*(msgctx: keccak256, domain: uint64): ECP2_BLS381 =
  ## Perform transformation of keccak-256 context (which must be already
  ## updated with ``message``) over domain ``domain`` to point in G2.
  var
    bebuf: array[8, byte]
    buffer: array[MODBYTES_384, byte]
    xre, xim: BIG_384
    x, one: FP2_BLS381
  # Copy context of `msgctx` which is keccak256(message)
  var ctx1 = msgctx
  var ctx2 = msgctx
  # Convert `domain` to its big-endian representation
  bigEndian64(addr bebuf[0], unsafeAddr domain)
  # Update hash context with domain value
  ctx1.update(bebuf)
  ctx2.update(bebuf)
  # Update hash context with coordinate marker
  bebuf[0] = 0x01
  ctx1.update(bebuf.toOpenArray(0, 0))
  bebuf[0] = 0x02
  ctx2.update(bebuf.toOpenArray(0, 0))
  # Obtain result hash
  var xrehash = ctx1.finish()
  var ximhash = ctx2.finish()
  # Clear contexts
  ctx1.clear()
  ctx2.clear()
  discard xre.fromBytes(xrehash.data)
  discard xim.fromBytes(ximhash.data)
  # Convert (xre, xim) to FP2.
  x.fromBigs(xre, xim)
  # Set FP2 One
  one.setOne()
  while true:
    # Without normalization of `x` 32bit version will fail
    norm(x)
    if ECP2_BLS381_setx(addr result, addr x) == 1:
      break
    # Increment `x` by FP2(1, 0)
    x = add(x, one)
  # Get biggest Y
  let negy = neg(result.y)
  # Reverting sign of ``y`` only when ``y`` less then negated one.
  if cmp(result.y, negy) < 0:
   result.y = negy
  # Scale with G2 CoFactor
  result = mulCoFactor(result)

proc atePairing*(pointG2: GroupG2, pointG1: GroupG1): FP12_BLS381 =
  ## Pairing `magic` function.
  PAIR_BLS381_ate(addr result, unsafeAddr pointG2, unsafeAddr pointG1)
  PAIR_BLS381_fexp(addr result)

proc doublePairing*(pointG2_1: GroupG2, pointG1_1: GroupG1,
                    pointG2_2: GroupG2, pointG1_2: GroupG1): bool =
  ## Double pairing `magic` function.
  var v: FP12_BLS381
  var npoint = neg(pointG1_1)
  PAIR_BLS381_double_ate(addr v, unsafeAddr pointG2_1, addr npoint,
                         unsafeAddr pointG2_2, unsafeAddr pointG1_2)
  PAIR_BLS381_fexp(addr v)

  if FP12_BLS381_isunity(addr v) == 1:
    result = true

proc multiPairing*(pointG2_1: GroupG2, pointG1_1: GroupG1,
                   pointG2_2: GroupG2, pointG1_2: GroupG1): bool =
  ## New multi-pairing mechanism function.
  var r: array[AteBitsCount, FP12_BLS381]
  var v: FP12_BLS381
  var npoint = neg(pointG1_1)
  PAIR_BLS381_initmp(addr r[0])
  PAIR_BLS381_another(addr r[0], unsafeAddr pointG2_1, addr npoint)
  PAIR_BLS381_another(addr r[0], unsafeAddr pointG2_2, unsafeAddr pointG1_2)
  PAIR_BLS381_miller(addr v, addr r[0])
  PAIR_BLS381_fexp(addr v)

  if FP12_BLS381_isunity(addr v) == 1:
    result = true

proc random*(a: var BIG_384) =
  ## Generates random big number `bit by bit` using nimcrypto's sysrand
  ## generator.
  var
    rndBuffer: array[MODBYTES_384, byte]
    rndByte: byte
    j: int32
    k: int32

  doAssert(randomBytes(rndBuffer) == MODBYTES_384)
  let length = 8 * MODBYTES_384
  a.zero()
  for i in 0..<length:
    if j == 0:
      rndByte = rndBuffer[k]
      inc(k)
    else:
      rndByte = rndByte shr 1
    let bit = Chunk(rndByte and 1'u8)
    BIG_384_shl(a, 1)
    a[0] = a[0] + bit
    inc(j)
    j = j and 0x07

proc randomNum*(a: var BIG_384, q: BIG_384) =
  ## Generates random big number `bit by bit` over modulo ``q`` using
  ## nimcrypto's sysrand generator.
  var
    d: DBIG_384
    rndBuffer: array[MODBYTES_384 * 2, byte]
    rndByte: byte
    j: int32
    k: int32

  doAssert(randomBytes(rndBuffer) == MODBYTES_384 * 2)
  let length = 2 * BIG_384_nbits(q)
  a.zero()

  for i in 0..<length:
    if j == 0:
      rndByte = rndBuffer[k]
      inc(k)
    else:
      rndByte = rndByte shr 1
    let bit = Chunk(rndByte and 1'u8)
    BIG_384_dshl(d, 1)
    d[0] = d[0] + bit
    inc(j)
    j = j and 0x07
  BIG_384_dmod(a, d, q)
