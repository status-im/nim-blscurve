# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

{.push raises: [Defect].}

import stew/[byteutils]
import milagro

var CURVE_Order* {.importc: "CURVE_Order_BLS12381".}: BIG_384
var FIELD_Modulus* {.importc: "Modulus_BLS12381".}: BIG_384
var FrobeniusReal {.importc: "Fra_BLS12381".}: BIG_384
var FrobeniusIm {.importc: "Frb_BLS12381".}: BIG_384
let FrobeniusConst = block:
  var result: FP2_BLS12381
  FP2_BLS12381_from_BIGs(addr result, FrobeniusReal, FrobeniusIm)
  # SEXTIC_TWIST_BLS12381 = MType
  FP2_BLS12381_inv(addr result, addr result)
  FP2_BLS12381_norm(addr result)
  result
var CurveNegX* {.importc: "CURVE_Bnx_BLS12381".}: BIG_384
  ## Curve parameter, it is negative i.e. -x

const
  AteBitsCount* = 65 ## ATE_BITS_BLS12381 value

type
  Domain* = array[8, byte]

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
  BIG_384_nbits(a)

proc copy*(dst: var BIG_384, src: BIG_384) {.inline.} =
  ## Copy value if big integer ``src`` to ``dst``.
  BIG_384_copy(dst, src)

proc setOne*(dst: var FP2_BLS12381) {.inline.} =
  ## Set value of ``dst`` to FP2.one
  FP2_BLS12381_one(addr dst)

proc add*(dst: var FP2_BLS12381, x: FP2_BLS12381, y: FP2_BLS12381) {.inline.} =
  ## Set ``dst`` to ``x + y``.
  FP2_BLS12381_add(addr dst, unsafeAddr x, unsafeAddr y)

proc add*(x: FP2_BLS12381, y: FP2_BLS12381): FP2_BLS12381 {.inline.} =
  ## Returns ``x + y``.
  FP2_BLS12381_add(addr result, unsafeAddr x, unsafeAddr y)

proc sub*(dst: var FP2_BLS12381, x: FP2_BLS12381, y: FP2_BLS12381) {.inline.} =
  ## Set ``dst`` to ``x - y``.
  FP2_BLS12381_sub(addr dst, unsafeAddr x, unsafeAddr y)

proc sub*(x: FP2_BLS12381, y: FP2_BLS12381): FP2_BLS12381 {.inline.} =
  ## Returns ``x - y``.
  FP2_BLS12381_sub(addr result, unsafeAddr x, unsafeAddr y)

proc shiftr*(a: var BIG_384, bits: int) {.inline.} =
  ## Shift big integer ``a`` to the right by ``bits`` bits.
  BIG_384_shr(a, cint(bits))

proc norm*(a: BIG_384) {.inline.} =
  ## Normalize big integer value.
  ## All digits of the input are reduced ``mod 2^BASEBITS``.
  discard BIG_384_norm(a)

proc norm*(a: var FP_BLS12381) {.inline.} =
  ## Normalize FP field member.
  FP_BLS12381_norm(addr a)

proc norm*(a: var FP2_BLS12381) {.inline.} =
  ## Normalize FP2 field number.
  FP2_BLS12381_norm(addr a)

proc sqr*(x: FP_BLS12381): FP_BLS12381 {.inline.} =
  ## Retruns ``x ^ 2``.
  FP_BLS12381_sqr(addr result, unsafeAddr x)

proc rhs*(x: FP_BLS12381): FP_BLS12381 {.inline.} =
  ## Returns ``x ^ 3 + b``.
  ECP_BLS12381_rhs(addr result, unsafeAddr x)

proc sqr*(x: FP2_BLS12381): FP2_BLS12381 {.inline.} =
  ## Retruns ``x ^ 2``.
  FP2_BLS12381_sqr(addr result, unsafeAddr x)

func isSquare*(a: FP2_BLS12381): bool {.inline.} =
  ## Returns true if ``a`` is a square in the FP2 extension field
  FP2_BLS12381_qr(unsafeAddr a) == 1

proc sqrt*(a: var FP2_BLS12381, b: FP2_BLS12381): bool {.inline.} =
  ## ``a ≡ sqrt(b) (mod q)``
  ## Returns true if b is a quadratic residue
  ## (i.e. congruent to a perfect square mod q)
  result = b.isSquare()
  if result:
    FP2_BLS12381_sqrt(addr a, unsafeAddr b)

proc sqrt*(a: FP2_BLS12381): FP2_BLS12381 {.inline.} =
  ## ``result ≡ sqrt(a) (mod q)``
  FP2_BLS12381_sqrt(addr result, unsafeAddr a)

proc pow*(a: FP2_BLS12381, b: BIG_384): FP2_BLS12381 {.inline.} =
  ## Compute ``result = a^b (mod q)``
  FP2_BLS12381_pow(addr result, unsafeAddr a, b)

proc nres*(a: BIG_384): FP_BLS12381 {.inline.} =
  ## Convert big integer value to residue form mod Modulus.
  FP_BLS12381_nres(addr result, a)

proc cmp*(a: BIG_384, b: BIG_384): int {.inline.} =
  ## Compares two big integers, inputs must be normalized externally
  ##
  ## Returns ``-1`` if ``a < b``, ``0`` if ``a == b``, ``1`` if ``a > b``
  int BIG_384_comp(a, b)

proc iszilch*(a: BIG_384): bool {.inline.} =
  ## Returns ``true`` if ``a`` is zero.
  bool BIG_384_iszilch(a)

proc iszilch*(a: FP_BLS12381): bool {.inline.} =
  ## Returns ``true`` if ``a`` is zero.
  FP_BLS12381_iszilch(unsafeAddr a) == 1

proc cmp*(a: FP_BLS12381, b: FP_BLS12381): int {.inline.} =
  ## Compares two FP field members
  ##
  ## Returns ``-1`` if ``a < b``, ``0`` if ``a == b``, ``1`` if ``a > b``
  var ab, bb: BIG_384
  FP_BLS12381_redc(ab, unsafeAddr a)
  FP_BLS12381_redc(bb, unsafeAddr b)
  cmp(ab, bb)

proc cmp*(a: FP2_BLS12381, b: FP2_BLS12381): int {.inline.} =
  ## Compares two FP2 field members.
  ##
  ## Returns ``-1`` if ``a < b``, ``0`` if ``a == b``, ``1`` if ``a > b``
  result = cmp(a.b, b.b)
  if result == 0:
    result = cmp(a.a, b.a)

proc neg*(a: FP_BLS12381): FP_BLS12381 {.inline.} =
  ## Return negated copy of ``a``. ``result = -a``.
  result = a
  FP_BLS12381_neg(addr result, unsafeAddr a)

proc neg*(a: FP2_BLS12381): FP2_BLS12381 {.inline.} =
  ## Return negated copy of ``a``. ``result = -a``.
  result = a
  FP2_BLS12381_neg(addr result, unsafeAddr a)

proc neg*(a: var ECP2_BLS12381) {.inline.} =
  ## Negates point ``a``. On exit a = -a.
  ECP2_BLS12381_neg(addr a)

proc neg*(a: ECP2_BLS12381): ECP2_BLS12381 {.inline.} =
  ## Negates point ``a``. On exit result = -a.
  result = a
  ECP2_BLS12381_neg(addr result)

proc sub*(P: var ECP2_BLS12381, Q: ECP2_BLS12381) {.inline.} =
  ## In-place substract a point Q from P
  discard ECP2_BLS12381_sub(addr P, unsafeAddr Q)

proc neg*(a: ECP_BLS12381): ECP_BLS12381 {.inline.} =
  ## Negates point ``a``. On exit a = -a.
  result = a
  ECP_BLS12381_neg(addr result)

func psi*(P: var ECP2_BLS12381) {.inline.} =
  ## Multiply a elliptic curve point by the frobenius constant
  ## This is the "Psi: untwist-Frobenius-twist" operation
  {.noSideEffect.}:
    discard ECP2_BLS12381_frob(addr P, unsafeAddr FrobeniusConst)

proc inf*(a: var ECP_BLS12381) {.inline.} =
  ## Makes point ``a`` infinite.
  ECP_BLS12381_inf(addr a)

proc isinf*(a: ECP_BLS12381): bool {.inline.} =
  ## Check if ``a`` is infinite.
  var tmp = a
  ECP_BLS12381_isinf(addr tmp) != 0

proc isinf*(a: ECP2_BLS12381): bool {.inline.} =
  ## Check if ``a`` is infinite.
  var tmp = a
  ECP2_BLS12381_isinf(addr tmp) != 0

proc inv*(a: FP2_BLS12381): FP2_BLS12381 {.inline.} =
  ## Returns the reciprocal copy of ``a``
  ## ``result = 1/a``
  FP2_BLS12381_inv(addr result, unsafeAddr a)

proc rhs*(x: FP2_BLS12381): FP2_BLS12381 {.inline.} =
  ## Returns ``x ^ 3 + b``.
  ECP2_BLS12381_rhs(addr result, unsafeAddr x)

proc iszilch*(a: FP2_BLS12381): bool {.inline.} =
  ## Returns ``true`` if ``a`` is zero.
  FP2_BLS12381_iszilch(unsafeAddr a) == 1

proc cmov*(a: var FP2_BLS12381, b: FP2_BLS12381, c: bool) {.inline.} =
  ## Conditional copy of FP2 element (without branching)
  ## if c: a = b
  ## if not c: a is unchanged
  ## This is a constant time operation
  FP2_BLS12381_cmove(addr a, unsafeAddr b, cint(c))

proc cmov*(a: FP2_BLS12381, b: FP2_BLS12381, c: bool): FP2_BLS12381 {.inline.} =
  ## Conditional copy of FP2 element (without branching)
  ## if c: result = b
  ## if not c: result = a
  ## This is a constant time operation
  result = a
  FP2_BLS12381_cmove(addr result, unsafeAddr b, cint(c))

proc parity*(a: FP2_BLS12381): int {.inline.} =
  ## Returns parity for ``a``.
  var t: BIG_384
  FP_BLS12381_redc(t, unsafeAddr a.a)
  int BIG_384_parity(t)

proc parity*(a: FP_BLS12381): int {.inline.} =
  ## Returns parity for ``a``.
  var t: BIG_384
  FP_BLS12381_redc(t, unsafeAddr a)
  int BIG_384_parity(t)

proc parity*(a: BIG_384): int {.inline.} =
  ## Returns parity for ``a``.
  int BIG_384_parity(a)

func inf*(a: var ECP2_BLS12381) {.inline.} =
  ## Makes point ``a`` infinite.
  ECP2_BLS12381_inf(addr a)

proc affine*(a: var ECP_BLS12381) {.inline.} =
  ## Convert ``a`` from (x, y, z) to (x, y).
  ECP_BLS12381_affine(addr a)

proc affine*(a: var ECP2_BLS12381) {.inline.} =
  ## Convert ``a`` from (x, y, z) to (x, y, 1).
  ECP2_BLS12381_affine(addr a)

proc add*(a: var ECP2_BLS12381, b: ECP2_BLS12381) {.inline.} =
  ## Add point ``b`` to point ``a``.
  # ECP2_BLS12381_add() always return 0.
  discard ECP2_BLS12381_add(addr a, unsafeAddr b)

proc double*(a: var ECP2_BLS12381) {.inline.} =
  ## Doubles point ``a``.
  discard ECP2_BLS12381_dbl(addr a)

proc add*(a: var ECP_BLS12381, b: ECP_BLS12381) {.inline.} =
  ## Add point ``b`` to point ``a``.
  ECP_BLS12381_add(addr a, unsafeAddr b)

proc mul*(dst: var FP2_BLS12381, x: FP2_BLS12381, y: FP2_BLS12381) {.inline.} =
  ## Set ``dst`` to ``x * y``.
  FP2_BLS12381_mul(addr dst, unsafeAddr x, unsafeAddr y)

proc mul*(x: FP2_BLS12381, y: FP2_BLS12381): FP2_BLS12381 {.inline.} =
  ## Returns ``x * y``.
  FP2_BLS12381_mul(addr result, unsafeAddr x, unsafeAddr y)

proc mul*(a: var ECP2_BLS12381, b: BIG_384) {.inline.} =
  ## Multiply point ``a`` by big integer ``b``.
  ECP2_BLS12381_mul(addr a, b)

proc mul*(a: var ECP_BLS12381, b: BIG_384) {.inline.} =
  ## Multiply point ``a`` by big integer ``b``.
  ECP_BLS12381_mul(addr a, b)

proc get*(a: ECP2_BLS12381, x, y: var FP2_BLS12381): int {.inline.} =
  ## Get coordinates ``x`` and ``y`` from point ``a``.
  int ECP2_BLS12381_get(addr x, addr y, unsafeAddr a)

proc get*(a: ECP_BLS12381, x, y: var BIG_384): int {.inline.} =
  ## Get coordinates ``x`` and ``y`` from point ``a``.
  int ECP_BLS12381_get(x, y, unsafeAddr a)

proc `==`*(a, b: ECP_BLS12381): bool {.inline.} =
  ## Compare points ``a`` and ``b`` in ECP Group.
  ECP_BLS12381_equals(unsafeAddr a, unsafeAddr b) == 1

proc `==`*(a, b: ECP2_BLS12381): bool {.inline.} =
  ## Compare points ``a`` and ``b`` in ECP2 Group.
  ECP2_BLS12381_equals(unsafeAddr a, unsafeAddr b) == 1

proc `==`*(a, b: FP_BLS12381): bool {.inline.} =
  ## Compare field elements over FP.
  FP_BLS12381_equals(unsafeAddr a, unsafeAddr b) == 1

proc `==`*(a, b: FP2_BLS12381): bool {.inline.} =
  ## Compare field elements over FP2.
  FP2_BLS12381_equals(unsafeAddr a, unsafeAddr b) == 1

proc `==`*(a, b: FP12_BLS12381): bool {.inline.} =
  ## Compare field elements over FP12.
  FP12_BLS12381_equals(unsafeAddr a, unsafeAddr b) == 1

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

proc `$`*(r: FP_BLS12381): string =
  ## Return string representation of ``FP_BLS12381``.
  var c: BIG_384
  FP_BLS12381_redc(c, unsafeAddr r)
  $c

proc `$`*(w: FP2_BLS12381): string =
  ## Return string representation of ``FP2_BLS12381``.
  var wx = w
  var bx, by: BIG_384
  FP2_BLS12381_reduce(addr wx)
  FP_BLS12381_redc(bx, addr wx.a)
  FP_BLS12381_redc(by, addr wx.b)
  result = "["
  result.add($bx)
  result.add(", ")
  result.add($by)
  result.add("]")

proc `$`*(w: FP4_BLS12381): string =
  ## Return string representation of ``FP4_BLS12381``.
  result = "["
  result.add($w.a)
  result.add(", ")
  result.add($w.b)
  result.add("]")

proc `$`*(w: FP12_BLS12381): string =
  ## Return string representation of ``FP12_BLS12381``.
  result = "["
  result.add($w.a)
  result.add(", ")
  result.add($w.b)
  result.add(", ")
  result.add($w.c)
  result.add("]")

proc `$`*(p: ECP_BLS12381): string =
  ## Return string representation of ``ECP_BLS12381``.
  if p.isinf():
    result = "INFINITY"
  else:
    var x, y: BIG_384
    var px = p
    ECP_BLS12381_affine(addr px)
    FP_BLS12381_redc(x, addr px.x)
    FP_BLS12381_redc(y, addr px.y)
    result = "("
    result.add($x)
    result.add(", ")
    result.add($y)
    result.add(")")

proc `$`*(p: ECP2_BLS12381): string =
  ## Return string representation of ``ECP2_BLS12381``.
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

func setx*(p: var ECP2_BLS12381, x: FP2_BLS12381, greatest: bool): int =
  ## Set value of ``p`` using just ``x`` coord with care to ``greatest``.
  ##
  ## This is custom `setx` procedure which works in way compatible to
  ## rust's library https://github.com/zkcrypto/pairing.
  var y, negy: FP2_BLS12381
  ECP2_BLS12381_rhs(addr y, unsafeAddr x)
  if not y.isSquare():
    ECP2_BLS12381_inf(addr p)
    result = 0
  else:
    FP2_BLS12381_sqrt(addr y, addr y)
    FP2_BLS12381_copy(addr p.x, unsafeAddr x)
    FP2_BLS12381_copy(addr negy, addr y)
    FP2_BLS12381_neg(addr negy, addr negy)
    if not((cmp(y, negy) < 0) xor greatest):
      FP2_BLS12381_copy(addr p.y, addr negy)
    else:
      FP2_BLS12381_copy(addr p.y, addr y)
    FP2_BLS12381_one(addr p.z)
    result = 1

func setx*(p: var ECP_BLS12381, x: BIG_384, greatest: bool): int =
  ## Set value of ``p`` using just ``x`` coord with care to ``greatest``.
  ##
  ## This is custom `setx` procedure which works in way compatible to
  ## rust's library https://github.com/zkcrypto/pairing.
  var rhs, negy, sqrt_hint: FP_BLS12381
  var t: BIG_384
  FP_BLS12381_nres(addr rhs, x)
  ECP_BLS12381_rhs(addr rhs, addr rhs)
  if FP_BLS12381_qr(addr rhs, addr sqrt_hint) == 0:
    p.inf()
    result = 0
  else:
    FP_BLS12381_nres(addr p.x, x)
    FP_BLS12381_sqrt(addr p.y, addr rhs, addr sqrt_hint)
    FP_BLS12381_redc(t, addr p.y)
    FP_BLS12381_neg(addr negy, addr p.y)
    FP_BLS12381_norm(addr negy)
    if not((cmp(p.y, negy) < 0) xor greatest):
      p.y = negy
    FP_BLS12381_reduce(addr p.y)
    FP_BLS12381_one(addr p.z)
    result = 1

proc fromBigs*(p: var FP2_BLS12381, x, y: BIG_384) {.inline.} =
  ## Set value of ``p`` from two big integers ``x`` and ``y``.
  FP2_BLS12381_from_BIGs(addr p, x, y)

proc fromFPs*(p: var FP2_BLS12381, x, y: FP_BLS12381) {.inline.} =
  ## Set value of ``p`` from two big integers ``x`` and ``y``.
  FP2_BLS12381_from_FPs(addr p, x, y)

proc generator1*(): ECP_BLS12381 {.inline.} =
  ECP_BLS12381_generator(addr result)

proc generator2*(): ECP2_BLS12381 {.inline.} =
  ECP2_BLS12381_generator(addr result)

proc isOnCurve*(x, y: FP_BLS12381 or FP2_BLS12381): bool =
  ## Returns ``true`` if point is on curve or points to infinite.
  if x.iszilch() and y.iszilch():
    true
  else:
    sqr(y) == rhs(x)

proc toBytes*(a: BIG_384, res: var openArray[byte]): bool =
  ## Serialize big integer ``a`` to ``res``. Length of ``res`` array
  ## must be ``MODBYTES_384``.
  ##
  ## Returns ``true`` if ``a`` was succesfully serialized,
  ## ``false`` otherwise.
  if len(res) == MODBYTES_384:
    var c: BIG_384
    BIG_384_copy(c, a)
    # BIG_384_norm() function in Milagro operates inplace.
    discard BIG_384_norm(c)
    for i in countdown(MODBYTES_384 - 1, 0):
      res[i] = byte(c[0] and 0xFF)
      discard BIG_384_fshr(c, 8)
    true
  else:
    false

proc getBytes*(a: BIG_384): array[MODBYTES_384, byte] =
  ## Serialize big integer ``a`` and return array of bytes.
  discard toBytes(a, result)

proc toHex*(a: BIG_384): string {.inline.} =
  ## Serialize big integer ``a`` and return hexadecimal string
  ## representation, if serialization failed empty string will be returned.
  toHex(getBytes(a))

func fromBytes*(res: var BIG_384, a: openArray[byte]): bool =
  ## Unserialize big integer from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``MODBYTES_384_29``.
  zeroMem(res.addr, sizeof(res))
  let length = if len(a) > MODBYTES_384: MODBYTES_384 else: len(a)
  for i in 0..<length:
    discard BIG_384_fshl(res, 8)
    res[0] = res[0] + cast[Chunk](a[i])
  true

func fromBytes*(res: var DBIG_384, a: openArray[byte]): bool =
  ## Unserialize double big integer from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``2*MODBYTES_384_29``.

  # TODO: there is no length check in Milagro BIG_384_29_dfromBytesLen
  #       is that normal?
  zeroMem(res.addr, sizeof(res))
  for rawByte in a:
    BIG_384_dshl(res, 8)
    res[0] = res[0] + cast[Chunk](rawByte)
  true

func fromHex*(res: var BIG_384, a: string): bool {.inline.} =
  ## Unserialize big integer from hexadecimal string ``a`` to ``res``.
  ##
  ## Returns ``true`` if conversion was successful.
  try:
    fromBytes(res, hexToSeqByte(a))
  except ValueError, IndexError:
    # TODO: change to exception-free
    # https://github.com/status-im/nim-blscurve/issues/57
    false

proc toBytes*(point: ECP2_BLS12381, res: var openArray[byte]): bool =
  ## Serialize ECP2(G2) point ``point`` to ``res``. Length of ``res`` array
  ## must be at least ``MODBYTES_384 * 2``.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  ##
  ## Returns ``true`` if ``a`` was succesfully serialized,
  ## ``false`` otherwise.
  if len(res) == MODBYTES_384 * 2:
    var x, y: FP2_BLS12381
    var x0, x1: BIG_384
    if point.get(x, y) == -1:
      zeroMem(addr res[0], MODBYTES_384 * 2)
      res[0] = res[0] or (1'u8 shl 7) or (1'u8 shl 6)
      true
    else:
      FP_BLS12381_redc(x0, addr x.a)
      FP_BLS12381_redc(x1, addr x.b)
      var negy = y.neg()
      discard toBytes(x1, res.toOpenArray(0, MODBYTES_384 - 1))
      discard toBytes(x0, res.toOpenArray(MODBYTES_384, MODBYTES_384 * 2 - 1))
      res[0] = res[0] or (1'u8 shl 7)
      if cmp(y, negy) > 0:
        res[0] = res[0] or (1'u8 shl 5)
      true
  else:
    false

proc getBytes*(point: ECP2_BLS12381): array[MODBYTES_384 * 2, byte] =
  ## Serialize ECP2(G2) point ``point`` and return array of bytes.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  discard toBytes(point, result)

proc toHex*(point: ECP2_BLS12381): string =
  ## Serialize ECP2(G2) point ``point`` and return hexadecimal string
  ## representation, if serialization failed empty string will be returned.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  toHex(getBytes(point))

func fromBytes*(res: var ECP2_BLS12381, data: openArray[byte]): bool =
  ## Unserialize ECP2(G2) point from array of bytes ``data``.
  ##
  ## This procedure supports only compressed form of serialization.
  ##
  ## Returns ``true`` on success, ``false`` otherwise.
  result = false
  if len(data) == MODBYTES_384 * 2:
    if (data[0] and (1'u8 shl 7)) != 0:
      if (data[0] and (1'u8 shl 6)) != 0:
        # Infinity point
        # ensure all bytes are 0 except the first in constant-time
        result = data[0] == byte 0b11000000
        for i in 1 ..< data.len:
          result = result and (data[i] == byte 0)
        res.inf()
      else:
        var buffer: array[MODBYTES_384, byte]
        var x1, x0: BIG_384
        let greatest = (data[0] and (1'u8 shl 5)) != 0'u8
        copyMem(addr buffer[0], unsafeAddr data[0], MODBYTES_384)
        buffer[0] = buffer[0] and 0x1F'u8
        if x1.fromBytes(buffer):
          copyMem(addr buffer[0], unsafeAddr data[MODBYTES_384], MODBYTES_384)
          if x0.fromBytes(buffer):
            {.noSideEffect.}:
              let over =
                x0.cmp(FIELD_Modulus) != -1 or
                x1.cmp(FIELD_Modulus) != -1
            if over:
              return false

            var x: FP2_BLS12381
            x.fromBigs(x0, x1)
            if res.setx(x, greatest) == 1:
              result = true
    else: # only compressed form is supported
      result = false
  else:
    result = false

func fromHex*(res: var ECP2_BLS12381, a: string): bool {.inline.} =
  ## Unserialize ECP2(G2) point from hexadecimal string ``a`` to ``res``.
  ##
  ## This procedure supports only compressed form of serialization.
  ##
  ## Returns ``true`` if conversion was successfull.
  try:
    fromBytes(res, hexToSeqByte(a))
  except ValueError, IndexError:
    # TODO: change to exception-free
    # https://github.com/status-im/nim-blscurve/issues/57
    false

proc toBytes*(point: ECP_BLS12381, res: var openArray[byte]): bool =
  ## Serialize ECP(G1) point ``point`` to ``res``. Length of ``res`` array
  ## must be ``MODBYTES_384``.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  ##
  ## Returns ``true`` if ``a`` was succesfully serialized,
  ## ``false`` otherwise.
  if len(res) == MODBYTES_384:
    var x, y: BIG_384
    let parity = point.get(x, y)
    if parity == -1:
      zeroMem(addr res[0], MODBYTES_384)
      res[0] = res[0] or (1'u8 shl 7) or (1'u8 shl 6)
      true
    else:
      var ny = nres(y)
      var negy = ny.neg()
      negy.norm()
      discard toBytes(x, res.toOpenArray(0, MODBYTES_384 - 1))
      if cmp(ny, negy) > 0:
        res[0] = res[0] or (1'u8 shl 5)
      res[0] = res[0] or (1'u8 shl 7)
      true
  else:
    false

proc getBytes*(point: ECP_BLS12381): array[MODBYTES_384, byte] =
  ## Serialize ECP(G1) point ``point`` and return array of bytes.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  discard toBytes(point, result)

proc toHex*(point: ECP_BLS12381): string =
  ## Serialize ECP(G1) point ``point`` and return hexadecimal string
  ## representation, if serialization failed empty string will be returned.
  ##
  ## This procedure serialize point in compressed form (e.g. only x coordinate).
  toHex(getBytes(point))

func fromBytes*(res: var ECP_BLS12381, data: openArray[byte]): bool =
  ## Unserialize ECP point from array of bytes ``data``.
  ##
  ## This procedure supports only compressed form of serialization.
  ##
  ## Returns ``true`` on success, ``false`` otherwise.
  if len(data) == MODBYTES_384:
    if (data[0] and (1'u8 shl 7)) != 0:
      if (data[0] and (1'u8 shl 6)) != 0:
        # Infinity point
        # ensure all bytes are 0 except the first in constant-time
        result = data[0] == byte 0b11000000
        for i in 1 ..< data.len:
          result = result and (data[i] == byte 0)
        res.inf()
      else:
        var x: BIG_384
        var buffer: array[MODBYTES_384, byte]
        copyMem(addr buffer[0], unsafeAddr data[0], MODBYTES_384)
        let greatest = (data[0] and (1'u8 shl 5)) != 0'u8
        buffer[0] = buffer[0] and 0x1F'u8
        if x.fromBytes(buffer):
          {.noSideEffect.}:
            let over = x.cmp(FIELD_Modulus) != -1
          if over:
            return false
          if res.setx(x, greatest) == 1:
            result = true
    else: # only compressed form is supported
      result = false
  else:
    result = false

func fromHex*(res: var ECP_BLS12381, a: string): bool {.inline.} =
  ## Unserialize ECP point from hexadecimal string ``a`` to ``res``.
  ##
  ## This procedure supports only compressed form of serialization.
  ##
  ## Returns ``true`` if conversion was successfull.
  try:
    fromBytes(res, hexToSeqByte(a))
  except ValueError, IndexError:
    # TODO: change to exception-free
    # https://github.com/status-im/nim-blscurve/issues/57
    false

proc atePairing*(pointG2: GroupG2, pointG1: GroupG1): FP12_BLS12381 =
  ## Pairing `magic` function.
  PAIR_BLS12381_ate(addr result, unsafeAddr pointG2, unsafeAddr pointG1)
  PAIR_BLS12381_fexp(addr result)

proc doublePairing*(pointG2_1: GroupG2, pointG1_1: GroupG1,
                    pointG2_2: GroupG2, pointG1_2: GroupG1): bool =
  ## Double pairing `magic` function.
  var v: FP12_BLS12381
  var npoint = neg(pointG1_1)
  PAIR_BLS12381_double_ate(addr v, unsafeAddr pointG2_1, addr npoint,
                         unsafeAddr pointG2_2, unsafeAddr pointG1_2)
  PAIR_BLS12381_fexp(addr v)
  FP12_BLS12381_isunity(addr v) == 1

proc multiPairing*(pointG2_1: GroupG2, pointG1_1: GroupG1,
                   pointG2_2: GroupG2, pointG1_2: GroupG1): bool =
  ## New multi-pairing mechanism function.
  var r: array[AteBitsCount, FP12_BLS12381]
  var v: FP12_BLS12381
  var npoint = neg(pointG1_1)
  PAIR_BLS12381_initmp(addr r[0])
  PAIR_BLS12381_another(addr r[0], unsafeAddr pointG2_1, addr npoint)
  PAIR_BLS12381_another(addr r[0], unsafeAddr pointG2_2, unsafeAddr pointG1_2)
  PAIR_BLS12381_miller(addr v, addr r[0])
  PAIR_BLS12381_fexp(addr v)
  FP12_BLS12381_isunity(addr v) == 1
