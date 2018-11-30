import algorithm
import nimcrypto/[sysrand, utils, hash, blake2]
import internals
export internals

var CURVE_Order* {.importc: "CURVE_Order_BLS381".}: BIG_384

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
  result = a
  FP_BLS381_neg(addr result, unsafeAddr a)

proc neg*(a: FP2_BLS381): FP2_BLS381 {.inline.} =
  result = a
  FP2_BLS381_neg(addr result, unsafeAddr a)

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
  result = int(ECP2_BLS381_get(addr x, addr y, unsafeAddr a))

proc get*(a: ECP_BLS381, x, y: var BIG_384): int {.inline.} =
  result = int(ECP_BLS381_get(x, y, unsafeAddr a))

proc setx*(p: var ECP2_BLS381, x: FP2_BLS381): int {.inline.} =
  result = int(ECP2_BLS381_setx(addr p, unsafeAddr x))

proc setx*(p: var ECP_BLS381, x: BIG_384, sign: int): int {.inline.} =
  result = int(ECP_BLS381_setx(addr p, x, cint(sign)))

proc generator1*(): ECP_BLS381 {.inline.} =
  ECP_BLS381_generator(addr result)

proc generator2*(): ECP2_BLS381 {.inline.} =
  ECP2_BLS381_generator(addr result)

proc `==`*(a: FP12_BLS381, b: FP12_BLS381): bool {.inline.} =
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
    var px = p
    var x, y: FP2_BLS381
    discard ECP2_BLS381_get(addr x, addr y, addr px)
    result = "("
    result.add($x)
    result.add(", ")
    result.add($y)
    result.add(")")

proc toBytes*(a: BIG_384, res: var array[MODBYTES_384, byte]) =
  ## Serialize big integer ``a`` to ``res``.
  var c: BIG_384
  BIG_384_copy(c, a)
  # BIG_384_norm() function in Milagro operates inplace.
  discard BIG_384_norm(c)
  for i in countdown(MODBYTES_384 - 1, 0):
    res[i] = byte(c[0] and 0xFF)
    BIG_384_fshr(c, 8)

proc fromBytes*(res: var BIG_384, a: openarray[byte]): bool =
  ## Unserialize big integer from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``MODBYTES_384_29``.
  let length = if len(a) > MODBYTES_384: MODBYTES_384 else: len(a)
  for i in 0..<length:
    discard BIG_384_fshl(res, 8)
    res[0] = res[0] + Chunk(a[i])
  result = true

# proc toBytes*(a: ECP2_BLS381, res: var array[MODBYTES_384 * 4, byte]) =
#   var aclone = a
#   var oct = Octet(max: MODBYTES_384 * 4, val: addr res[0])
#   ECP2_BLS381_toOctet(addr oct, addr aclone)

# proc toBytes*(a: ECP2_BLS381, res: var array[MODBYTES_384 * 4, byte],
#               compressed = false) =
#   if compressed:
#     discard
#   else:
#     var aclone = a
#     var oct = Octet(max: MODBYTES_384 * 4, val: addr res[0])
#     ECP2_BLS381_toOctet(addr oct, addr aclone)

proc fromBytes*(res: var ECP2_BLS381, a: openarray[byte]): bool =
  if len(a) < MODBYTES_384 * 4:
    result = false
  else:
    var oct = Octet(len: MODBYTES_384 * 4, max: MODBYTES_384 * 4,
                    val: unsafeAddr a[0])
    result = (ECP2_BLS381_fromOctet(addr res, addr oct) == 1)

proc toBytes*(a: ECP_BLS381, res: var array[MODBYTES_384 * 2 + 1, byte],
              compressed = false) =
  ## Serialize point ``a`` to ``res`` in compressed (if ``compressed ==
  ## true``) or uncompressed (default) form.
  var aclone = a
  var x, y: BIG_384

  discard ECP_BLS381_get(x, y, addr aclone)
  if compressed:
    res[0] = 0x02
    if BIG_384_parity(y) == 1: res[0] = 0x03
    BIG_384_toBytes(cast[ptr char](addr res[1]), x)
  else:
    res[0] = 0x04
    BIG_384_toBytes(cast[ptr char](addr res[1]), x)
    BIG_384_toBytes(cast[ptr char](addr res[MODBYTES_384 + 1]), y)

proc fromBytes*(res: var ECP_BLS381, a: openarray[byte]): bool =
  ## Unserialize big integer from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``MODBYTES_384_29 * 2 + 1`` for
  ## uncompressed signature, or at least ``MODBYTES_384_29 + 1`` for
  ## compressed signature.
  var oct: Octet
  let length = len(a)
  if length == MODBYTES_384 + 1:
    # Compressed form
    oct = Octet(len: MODBYTES_384 + 1,
                max: MODBYTES_384 + 1, val: unsafeAddr a[0])
    result = ECP_BLS381_fromOctet(addr res, addr oct) == 1
  elif length == MODBYTES_384 * 2 + 1:
    # Uncompressed form
    oct = Octet(len: MODBYTES_384 * 2 + 1,
                max: MODBYTES_384 * 2 + 1, val: unsafeAddr a[0])
    result = ECP_BLS381_fromOctet(addr res, addr oct) == 1
  else:
    result = false

proc toBytes*(a: FP12_BLS381, res: var array[MODBYTES_384 * 12, byte]) =
  ## Serialize FP12 ``a`` to ``res``.
  var oct = Octet(max: MODBYTES_384 * 12, val: addr res[0])
  FP12_BLS381_toOctet(addr oct, unsafeAddr a)

proc fromBytes*(res: var FP12_BLS381, a: openarray[byte]): bool =
  ## Unserialize FP12 from ``a`` to ``res``.
  ## Length of ``a`` must be at least ``MODBYTES_384_29 * 12``.
  if len(a) != MODBYTES_384 * 12:
    result = false
  else:
    var oct = Octet(len: MODBYTES_384 * 12, max: MODBYTES_384 * 12,
                    val: unsafeAddr a[0])
    result = (FP12_BLS381_fromOctet(addr res, addr oct) == 1)

proc mapit*(hash: MDigest[384]): ECP_BLS381 =
  ## Map hash value ``hash`` to ECP
  var buffer: array[MODBYTES_384, byte]
  let pos = MODBYTES_384 - len(hash.data)
  copyMem(addr buffer[pos], unsafeAddr hash.data[0], len(hash.data))
  var oct = Octet(len: MODBYTES_384, max: MODBYTES_384,
                  val: addr buffer[0])
  ECP_BLS381_mapit(addr result, addr oct)

proc mapit2*(hash: MDigest[384]): ECP2_BLS381 =
  ## Map hash value ``hash`` to ECP2
  var buffer: array[MODBYTES_384, byte]
  let pos = MODBYTES_384 - len(hash.data)
  copyMem(addr buffer[pos], unsafeAddr hash.data[0], len(hash.data))
  var oct = Octet(len: MODBYTES_384, max: MODBYTES_384,
                  val: addr buffer[0])
  ECP2_BLS381_mapit(addr result, addr oct)

proc atePairing*(pointG2: GroupG2, pointG1: GroupG1): FP12_BLS381 =
  ## Pairing `magic` function.
  PAIR_BLS381_ate(addr result, unsafeAddr pointG2, unsafeAddr pointG1)
  PAIR_BLS381_fexp(addr result)

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

proc `==`*(a, b: ECP_BLS381): bool =
  ## Compare points ``a`` and ``b`` in ECP Group.
  result = (ECP_BLS381_equals(unsafeAddr a, unsafeAddr b) == 1)

proc `==`*(a, b: ECP2_BLS381): bool =
  ## Compare points ``a`` and ``b`` in ECP2 Group.
  result = (ECP2_BLS381_equals(unsafeAddr a, unsafeAddr b) == 1)
