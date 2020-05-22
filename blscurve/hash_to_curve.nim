# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Hash to Elliptic curve implementation for BLS12-381.
# - IETF Standard Draft: https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05
#   - Algorithm description in section 8.7
#   - This includes a specific appendix for BLS12-381 (Appendix C)
# - IETF Implementation: https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
#   - The following can be used as a test vector generator:
#     https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/6cf7fa97/poc/suite_bls12381g2.sage
# - Ethereum Foundation implementation: https://github.com/ethereum/py_ecc
#   - Specific PR: https://github.com/ethereum/py_ecc/pull/83/files

# This file has a companion markdown file with the relevant part of the standard.

# Implementation
# ----------------------------------------------------------------------
#
# Implementation notes:
#   Several parameters are known at compile-time, in particular the domain separation tag.
#   The spec requires creating a `dst_prime` with appended data that can be created at compile-time.
#   We choose to do so to avoid heap-allocation and the GC in crypto codepath.
#   The price is a bigger codegen due to the DSTs used:
#   - BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_POP_ for signatures
#   - BLS_POP_BLS12381G2-SHA256-SSWU-RO-_POP_ for proof of possesions

{.push raises: [Defect], gcsafe, noSideEffect.}

import
  # Status libraries
  nimcrypto/sha2, stew/endians2,
  # Internal
  ./milagro, ./hkdf, ./common

func ceilDiv(a, b: int): int {.used.} =
  ## ceil division
  ## ceil(a / b)
  (a + b - 1) div b

func expandMessageXMD[B: byte|char], len_in_bytes: static int](
       H: typedesc,
       output: var array[len_in_bytes, byte],
       msg: openArray[B],
       domainSepTag: static string,
     ) =
  ## Arguments:
  ## - `H` A cryptographic hash function
  ## - `msg`, a byte string containing the message to hash
  ## - `domainSepTag` (spec DST), a byte string that acts as a domain separation tag
  ## - `output`, a buffer of size `len_in_bytes`.
  ## The output will be filled with a pseudo random byte string
  ## the size of the preallocated buffer.
  ## Provided the `H` is indistinguishable from a random oracle
  ## the `output` will also be indistinuishable
  const
    b_in_bytes = H.bits  # b_in_bytes, ceil(b / 8) for b the output size of H in bits.
                         # For example, for b = 256, b_in_bytes = 32.
    r_in_bytes = H.bsize # r_in_bytes, the input block size of H, measured in bytes.
                         # For example, for SHA-256, r_in_bytes = 64.
  static:
    when H is sha256:
      doAssert b_in_bytes == 32
      doAssert r_in_bytes == 64

  # Steps:
  # 1.  ell = ceil(len_in_bytes / b_in_bytes)
  # 2.  ABORT if ell > 255
  # 3.  DST_prime = DST || I2OSP(len(DST), 1)
  # 4.  Z_pad = I2OSP(0, r_in_bytes)
  # 5.  l_i_b_str = I2OSP(len_in_bytes, 2)
  # 6.  b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
  # 7.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  # 8.  for i in (2, ..., ell):
  # 9.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
  # 10. pseudo_random_bytes = b_1 || ... || b_ell
  # 11. return substr(pseudo_random_bytes, 0, len_in_bytes)

  const ell = ceil(len_in_bytes)
  static: doAssert ell <= 255, "Please implement the \"oversized\" part of the Hash-To-Curve spec"

  const dst_prime = domainSepTag & $char(byte(domainSepTag.len))
  static: doAssert dst_prime.len == domainSepTag.len + 1

  const z_pad = default(array[r_in_bytes, byte])
  const l_i_b_str = toBytesBE(uint16(len_in_bytes))

  var ctx: H

  ctx.init()
  let b_0 = block:
    ctx.update(z_pad)
    ctx.update(msg)
    ctx.update(l_i_b_str)
    ctx.update([byte 0])
    ctx.update(dst_prime)
    ctx.finish()
    # burnMem?

  ctx.init()
  var b_1 = block:
    ctx.update(b_0.data)
    ctx.update([byte 1])
    ctx.update(dst_prime)
    ctx.finish()

  var cur = 0

  template copyFrom(output: var array, bi: array, cur: var int) =
    var b_index = 0
    while cur < min(b_1.len, len_in_bytes):
      output[cur] = bi[b_index]
      inc cur
      inc b_index

  output.copyFrom(b_1, cur)

  var b_i{.noInit.}: array[H.bits div 8, byte]

  template strxor(b_i1: var array, b0: array): untyped =
    for i in 0 ..< b_i1.len:
      b_i1[i] = b_i1[i] xor b0[i]

  for i in 2 ..< ell:
    ctx.init()
    if i == 2:
      strxor(b_1, b_0)
      ctx.update(b_1)
    else:
      strxor(b_i, b_0)
      ctx.update(b_i)
    ctx.update([byte i])
    ctx.update(dst_prime)
    discard ctx.finish(b_i)
    output.copyFrom(b_i, cur)
    if cur == len_in_bytes:
      break

  # burnMem?

func hashToFieldFP2[B: byte|char, count: static int](
        H: typedesc,
        output: var array[count, FP2_BLS381],
        msg: openArray[B],
        domainSepTag: static string,
      ) =
  ## Implementation of hash_to_field for the G2 curve of BLS12-381
  ## https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-5.2
  ##
  ## Inputs
  ## - msg: the message to hash
  ## - count: the number of element of FP2 to output
  ## - output: the output buffer
  ## - domainSepTag: A domain separation tag (DST)
  ##   that MUST include a protocol identification string
  ##   SHOULD include a protocol version number.
  ##
  ## Outputs
  ## - `count` points on FP2

  const
    L_BLS = 64 # ceil((ceil(log2(p)) + k) / 8), where k is the security
               # parameter of the cryptosystem (e.g., k = 128)
    m = 2      # Extension degree of FP2

  # Steps:
  # 1. len_in_bytes = count * m * L
  # 2. pseudo_random_bytes = expand_message(msg, DST, len_in_bytes)
  # 3. for i in (0, ..., count - 1):
  # 4.   for j in (0, ..., m - 1):
  # 5.     elm_offset = L * (j + i * m)
  # 6.     tv = substr(pseudo_random_bytes, elm_offset, L)
  # 7.     e_j = OS2IP(tv) mod p
  # 8.   u_i = (e_0, ..., e_(m - 1))
  # 9. return (u_0, ..., u_(count - 1))
  const len_in_bytes = count * m * L

  var pseudo_random_bytes{.noInit.}: array[len_bytes, byte]
  sha256.expandMessageXMD(pseudo_random_bytes, msg, domainSepTag)

  for i in 0 ..< count:
    var e_0{.noInit.}, e_1{.noInit.}: BIG_384
    var de_j{.noInit.}: DBIG_384 # Need a DBIG, L = 64 bytes = 512-bit > 384-bit

    template loopIter(e_j: untyped, j: range[1..m]): untyped {.dirty.} =
      ## for j in 0 ..< m
      let elm_offset = L_BLS * (j + i * m)
      template tv: untyped = pseudo_random_bytes.toOpenArray(elm_offset, L-1)
      discard de_j.fromBytes(tv)
      {.noSideEffect.}:
        BIG_384_dmod(e_j, de_j, FIELD_Modulus)

    loopIter(e_0, 0)
    loopIter(e_1, 1)
    output[i].fromBigs(e_0, e_1)

func toFP2(x, y: uint64): FP2_BLS381 =
  ## Convert a complex tuple x + iy to FP2
  # TODO: the result does not seem to need zero-initialization
  var xBig, yBig: BIG_384

  discard xBig.fromBytes(x.toBytesBE())
  discard yBig.fromBytes(y.toBytesBE())

  result.fromBigs(xBig, yBig)

func hexToFP2(x, y: string): FP2_BLS381 =
  ## Convert a complex tuple x + iy to FP2
  # TODO: the result does not seem to need zero-initialization
  var xBig, yBig: BIG_384

  discard xBig.fromHex(x)
  discard yBig.fromHex(y)

  result.fromBigs(xBig, yBig)

func isSquare(a: FP2_BLS381): bool =
  ## Returns true if ``a`` is a square in the FP2 field
  ## This is NOT a constant-time operation (Milagro has branches)

  # Constant-time implementation:
  #
  # is_square(x) := { True,  if x^((q - 1) / 2) is 0 or 1 in F;
  #                 { False, otherwise.
  #
  # In an extension field of order q:
  #   q - 1 (mod q) ≡ -1 (mod q)
  #
  # For now, we use Milagro built-in sqrt which returns true if
  # a is a quadratic residue (congruent to a perfect square mod q)
  # https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-4
  var tmp: FP2_BLS381
  result = sqrt(tmp, a)

func isNeg(a: FP2_BLS381): bool =
  ## Returns the "negative sign" (mod q) of a value
  ## a is negative when a (mod q) > -a (mod q)
  ## https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-4.1.1

  let neg = neg(a)
  result = cmp(a, neg) < 0

func mapToIsoCurveSimpleSWU_G2(u: FP2_BLS381): tuple[x, y: FP2_BLS381] =
  ## Implementation of map_to_curve_simple_swu
  ## to map an element of FP2 to a curve isogenous
  ## to the G2 curve of BLS12-381 curve.
  ##
  ## SWU stands for Shallue-van de Woestijne-Ulas mapping
  ## described in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-6.5.2
  ##
  ## Input:
  ## - u, an element of FP2
  ##
  ## Output:
  ## - (x, y), a point on G'2, a curve isogenous to G2 curve of BLS12-381

  {.noSideEffect.}: # Only globals accessed are A, B, Z, c1, c2.
                    # we use globals to ensure they are computed only once.
    let # Constants, See 8.9.2. BLS12-381 G2 suite
      A {.global.} = toFP2(   0,  240)   # A' = 240 * I
      B {.global.} = toFP2(1012, 1012)   # B' = 1012 * (1+I)
      Z {.global.} = neg toFP2(2, 1)     # Z  = -(2+I)
      c1 {.global.} = neg mul(B, inv(A)) # -B/A
      c2 {.global.} = neg inv(Z)         # -1/Z

    var one {.global.} = block:
      # TODO, we need an increment procedure
      #       this is incredibly inefficient
      var one: FP2_BLS381
      setOne(one)
      one

  {.noSideEffect.}:
    let tv1 = mul(Z, sqr(u))
    var tv2 = sqr(tv1)
    var x1 = add(tv1, tv2)
    x1 = inv(x1)                         # TODO: Spec defines inv0(0) == 0; inv0(x) == x^(q-2)
    let e1 = x1.isZilch()
    x1.add(x1, one)
    x1.cmov(c2, e1)                      # If (tv1 + tv2) == 0, set x1 = -1 / Z
    x1.mul(x1, c1)                       # x1 = (-B / A) * (1 + (1 / (Z² * u^4 + Z * u²)))
    var gx1 = sqr(x1)
    gx1.add(gx1, A)
    gx1.mul(gx1, x1)
    gx1.add(gx1, B)                      # gx1 = g(x1) = x1³ + A * x1 + B
    let x2 = mul(tv1, x1)                # x2 = Z * u² * x1
    tv2.mul(tv1, tv2)
    let gx2 = mul(gx1, tv2)              # gx2 = (Z * u²)³ * gx1
    let e2 = gx1.isSquare()
    let x = cmov(x2, x1, e2)             # If is_square(gx1), x = x1, else x = x2
    let y2 = cmov(gx2, gx1, e2)          # If is_square(gx1), y2 = gx1, else y2 = gx2
    var y = sqrt(y2)
    let e3 = u.isNeg() == y.isNeg()      # Fix sign of y
    y = cmov(neg y, y, e3)

  result.x = x
  result.y = y

func isogeny_map_G2(xp, yp: FP2_BLS381): ECP2_BLS381 =
  ## 3-isogeny map from a point P' (x', y') on G'2
  ## to a point P(x, y) on G2 curve of BLS12-381.
  ##
  ## https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#appendix-C.3

  {.noSideEffect.}: # Globals to ensure they are computed only once
    # Constants to compute x_numerator
    let k10 {.global.} = hexToFP2(
      "0x05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
      "0x05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"
    )
    let k11 {.global.} = hexToFP2(
      "0x00",
      "0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a"
    )
    let k12 {.global.} = hexToFP2( # The last nibble "e" is not a typo
      "0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e",
      "0x08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d"
    )
    let k13 {.global.} = hexToFP2(
      "0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1",
      "0x00"
    )
    # Constants to compute x_denominator
    let k20 {.global.} = hexToFP2(
      "0x00",
      "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63"
    )
    let k21 {.global.} = hexToFP2( # the last byte "9f" is not a typo
      "0x0c",
      "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f"
    )
    # Constants to compute y_numerator
    let k30 {.global.} = hexToFP2(
      "0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
      "0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"
    )
    let k31 {.global.} = hexToFP2(
      "0x00",
      "0x05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be"
    )
    let k32 {.global.} = hexToFP2(
      "0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c",
      "0x08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f"
    )
    let k33 {.global.} = hexToFP2(
      "0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10",
      "0x00"
    )
    # Constants to compute y_denominator
    let k40 {.global.} = hexToFP2(
      "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
      "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"
    )
    let k41 {.global.} = hexToFP2(
      "0x00",
      "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3"
    )
    let k42 {.global.} = hexToFP2(
      "0x12",
      "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99"
    )

  var xp2 = sqr(xp)
  norm(xp2)
  var xp3 = mul(xp, xp2)
  norm(xp3)

  {.noSideEffect.}: # TODO overload `+` and `*` for readability
    # xNum = k(1,3) * x'³ + k(1,2) * x'² + k(1,1) * x' + k(1,0)
    let xNum = block:
      var xNum = k13.mul(xp3)
      norm(xNum)
      xNum.add xNum, k12.mul(xp2)
      norm(xNum)
      xNum.add xNum, k11.mul(xp)
      norm(xNum)
      xNum.add xNum, k10
      xNum

    # xDen = x'² + k(2,1) * x' + k(2,0)
    let xDen = block:
      var xDen = xp2
      xDen.add xDen, k21.mul(xp)
      norm(xDen)
      xDen.add xDen, k20
      xDen

    # yNum = k(3,3) * x'³ + k(3,2) * x'² + k(3,1) * x' + k(3,0)
    let yNum = block:
      var yNum = k33.mul(xp3)
      norm(yNum)
      yNum.add yNum, k32.mul(xp2)
      norm(yNum)
      yNum.add yNum, k31.mul(xp)
      norm(yNum)
      yNum.add yNum, k30
      yNum

    # yDen = x'³ + k(4,2) * x'² + k(4,1) * x' + k(4,0)
    let yDen = block:
      var yDen = xp3
      yDen.add yDen, k42.mul(xp2)
      norm(yDen)
      yDen.add yDen, k41.mul(xp)
      norm(yDen)
      yDen.add yDen, k40
      yDen

  let x = xNum.mul inv(xDen)
  let y = yp.mul yNum.mul inv(yDen)

  let onCurve = bool ECP2_BLS381_set(addr result, unsafeAddr x, unsafeAddr y)
  assert onCurve

func mapToCurveG2(u: FP2_BLS381): ECP2_BLS381 =
  ## Map a field element FP2 to the G2 curve of BLS12-381
  ## using the simplified SWU method for pairing-friendly curves
  ##
  ## SWU stands for Shallue-van de Woestijne-Ulas
  ## Described in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-6.9.2
  ## And
  ## Wahby, R. and D. Boneh,
  ## "Fast and simple constant-time hashing to the BLS12-381 elliptic curve"
  ## https://eprint.iacr.org/2019/403

  # Hash to a curve isogenous to G2 BLS12-381
  let pointPrime = mapToIsoCurveSimpleSWU_G2(u)
  # 3-isogeny map P'(x', y') to G2 with coordinate P(x, y)
  result = isogeny_map_G2(pointPrime.x, pointPrime.y)

func clearCofactor(P: var ECP2_BLS381) =
  ## From any point on the elliptic curve of G2 of BLS12-381
  ## Obtain a point in the G2 subgroup
  ##
  ## Described in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-7
  #
  # Implementations, multiple implementations are possible in increasing order of speed:
  #
  # - The default, canonical, implementation is h_eff * P
  # - Scott et al, "Fast Hashing to G2 on Pairing-Friendly Curves", https://doi.org/10.1007/978-3-642-03298-1_8
  # - Fuentes-Castaneda et al, "Fast Hashing to G2 on Pairing-Friendly Curves", https://doi.org/10.1007/978-3-642-28496-0_25
  # - Budroni et al, "Hashing to G2 on BLS pairing-friendly curves", https://doi.org/10.1145/3313880.3313884
  # - Wahby et al "Fast and simple constant-time hashing to the BLS12-381 elliptic curve", https://eprint.iacr.org/2019/403
  #
  # In summary, the elliptic curve point multiplication is very expensive,
  # the fast methods uses bigint operations instead.

  # The method described in Wahby et al is implemented by Riad Wahby
  # in C at: https://github.com/kwantam/bls12-381_hash/blob/23c1930039f58606138459557677668fabc8ce39/src/curve2/ops2.c#L106-L204
  # following Budroni et al, "Efficient hash maps to G2 on BLS curves"
  # https://eprint.iacr.org/2017/419
  # Explanations for reference:
  # - Psi (ψ) - untwist-Frobenius-Twist function
  # - Addition-chain: https://en.wikipedia.org/wiki/Addition_chain / https://en.wikipedia.org/wiki/Addition-chain_exponentiation
  #
  # Budroni's paper mention an implementation in Milagro of BLS G2 hashmaps.
  # We reuse the relevant clearCofactor routines from ``ECP2_BLS381_mapit``
  # In Milagro terms: "Q -> x2Q -xQ -Q +F(xQ -Q) +F(F(2Q))"
  #
  # We use the notation from Riad Wahby
  # "P -> (x^2 - x - 1) P + (x - 1) psi(P) + psi(psi(2P))"
  #
  # with:
  # - P     (Wahby), Q   (Milagro) being the input point
  # - psi() (Wahby), F() (Milagro) being the untwist-Frobenius-twist mapping
  #
  # Note: CurveNegX = -x
  {.noSideEffect.}:
    var xP = P         # xP = P
    xP.mul(CurveNegX)  # xP = -x P
    var x2P = xP       # x2P = -x P
    x2P.mul(CurveNegX) # x2P = x²P

    neg(xP)            # xP = x P

    x2P.sub(xP)        # x2P = (x² - x) P
    x2P.sub(P)         # x2P = (x² - x - 1) P

    xP.sub(P)          # xP = (x - 1) P
    xP.psi()           # xP = (x - 1) psi(P) <=> psi(xP - P)

    P.double()         # P = 2 P
    P.psi()            # P = psi(2P)
    P.psi()            # P = psi(psi(2P))

    P.add(x2P)         # P = (x² - x - 1) P + psi(psi(2P))
    P.add(xP)          # P = (x² - x - 1) P + (x - 1) psi(P) + psi(psi(2P))

  P.affine()           # Convert from Jacobian coordinates (x', y', z') to affine (x, y, 1); (x is not the curve parameter here)

func hashToG2[B: byte|char](msg: openArray[B],
                            domainSepTag: static string): ECP2_BLS381 =
  ## Hash an arbitrary message to the G2 curve of BLS12-381
  ## The message should have an extra null byte after its declared length
  var u{.noInit.}: array[2, FP2_BLS381]

  sha256.hashToFieldFP2(u, msg, domainSepTag)

  result = mapToCurveG2(u[0])
  let Q1 = mapToCurveG2(u[1])

  result.add(Q1)
  result.clearCofactor()


# Unofficial test vectors for hashToG2 primitives
# ----------------------------------------------------------------------
#
# Those unofficial vectors are intended for debugging the building blocks of
# of the full hashToG2 function

when isMainModule:
  import stew/byteutils, nimcrypto/[sha2, hmac]

  proc hexToBytes(s: string): seq[byte] =
    if s.len != 0: return hexToSeqByte(s)

  proc displayECP2Coord(name: string, point: ECP2_BLS381) =
    echo "-------------------------------------------"
    echo "Point ", name, ':'
    echo "In jacobian projective coordinates (x, y, z)"
    echo point
    echo "In affine coordinate (x, y)"
    var x, y: FP2_BLS381
    discard ECP2_BLS381_get(x.addr, y.addr, point.unsafeAddr)
    echo "(", $x, ", ", $y, ")"

  proc toECP2(x, y: FP2_BLS381): ECP2_BLS381 =
    ## Create a point (x, y) on the G2 curve
    let onCurve = bool ECP2_BLS381_set(addr result, unsafeAddr x, unsafeAddr y)
    doAssert onCurve, "The coordinates (x, y) are not on the G2 curve"

  # Test vectors for hashToBaseFP2
  # ----------------------------------------------------------------------
  template testHashToBaseFP2(id, constants: untyped) =
    # https://github.com/mratsim/py_ecc/pull/1
    proc `test _ id`() =
      # We create a proc to avoid allocating too much globals.
      constants

      let pmsg = if msg.len == 0: nil
                 else: cast[ptr byte](msg[0].unsafeAddr)

      var ctx: HMAC[sha256]
      # Important: do we need to include the null byte at the end?
      let pointFP2 = hashToBaseFP2(
        ctx,
        pmsg, msg.len,
        ctr,
        dst
      )
      doAssert fp2 == pointFP2
      echo "Success hashToBaseFP2 ", astToStr(id)

    `test _ id`()

  block: # hashToBaseFP2
    testHashToBaseFP2 msg_ctr0:
      let
        msg = "msg"
        ctr = 0'i8
        dst = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"

      let fp2 = hexToFP2(
        x = "0x18df4dc51885b18ca0082a4966b0def46287930b8f1c0b673b11ac48d19c8899bc150d83fd3a7a1430b0de541742c1d4",
        y = "0x14eef8ca34b82d065d187a3904cb313dbb44558917cc5091574d9999b5ecfdd5af2fa3aea6e02fb253bf4ae670e72d55"
      )

  block:
    testHashToBaseFP2 msg_ctr1:
      let
        msg = "msg"
        ctr = 1'i8
        dst = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"

      let fp2 = hexToFP2(
        x = "0x14c81e3d32a930af141ff28f337e375bd7f2b35d006b2f6ba9a4c9eed7937e2b20d8b251fef776b0d497859510c9fad7",
        y = "0x05764cf5fe69554b971c5fe77eb3f3f9b89534547335b84ff02cd3d613bcd5e3037005b9226011a61a70b5bd0f0db570"
      )

  # Test vectors for mapToCurveG2
  # ----------------------------------------------------------------------
  template testMapToCurveG2(id, constants: untyped) =
    # https://github.com/sigp/incubator-milagro-crypto-rust/blob/49563467/src/bls381.rs#L209-L328
    # Themselves extracted from
    # https://github.com/kwantam/bls_sigs_ref/tree/master/python-impl
    proc `test _ id`() =
      # We create a proc to avoid allocating too much globals.
      constants

      let u0 = hexToFP2(u0x, u0y)
      let u1 = hexToFP2(u1x, u1y)

      let q0 = mapToCurveG2(u0)
      let q1 = mapToCurveG2(u1)

      var P = q0
      P.add(q1)

      displayECP2Coord("P (before clearCofactor)", P)
      P.clearCofactor()
      displayECP2Coord("P (after clearCofactor)", P)

      doAssert P == ecp
      echo "Success mapToCurveG2 ", astToStr(id)

    `test _ id`()

  block:
    testMapToCurveG2 MilagroRust_1:
      let
        u0x = "0x004ad233c619209060e40059b81e4c1f92796b05aa1bc6358d65e53dc0d657dfbc713d4030b0b6d9234a6634fd1944e7"
        u0y = "0x0e2386c82713441bc3b06a460bd81850f4bf376ea89c80b18c0881e855c58dc8e83b2fd23af983f4786508e30c42af01"
        u1x = "0x08a6a75e0a8d32f1e096f29047ea879dd34a5504218d7ce92c32c244786822fb73fbf708d167ad86537468249ec6df48"
        u1y = "0x07016d0e5e13cd65780042c6f7b4c74ae1c58da438c99582696818b5c229895b893318dcb87d2a65e557d4ebeb408b70"

      # Expected ECP2 (x, y: FP2) affine coordinates
      # x and y are complex coordinates in the form x' + iy'
      # that satisfy the BLS12-384 equation: y² = x³ + 4

      let ecp = toECP2(
        x = hexToFP2(
          # x = x' + iy'
          x = "0x04861c41efcc5fc56e62273692b48da25d950d2a0aaffb34eff80e8dbdc2d41ca38555ceb8554368436aea47d16056b5",
          y = "0x09db5217528c55d982cf05fc54242bdcd25f1ebb73372e00e16d8e0f19dc3aeabdeef2d42d693405a04c37d60961526a",
        ),
        y = hexToFP2(
          # y = x'' + iy''
          x = "0x177d05b95e7879a7ddbd83c15114b5a4e9846fde72b2263072dc9e60db548ccbadaacb92cc4952d4f47425fe3c5e0172",
          y = "0x0fc82c99b928ed9df12a74f9215c3df8ae1e9a3fa54c00897889296890b23a0edcbb9653f9170bf715f882b35c0b4647"
        )
      )

    testMapToCurveG2 PyECC_1_msg:
      # from hash_to_base_FP2("msg")
      let
        u0x = "0x18df4dc51885b18ca0082a4966b0def46287930b8f1c0b673b11ac48d19c8899bc150d83fd3a7a1430b0de541742c1d4"
        u0y = "0x14eef8ca34b82d065d187a3904cb313dbb44558917cc5091574d9999b5ecfdd5af2fa3aea6e02fb253bf4ae670e72d55"
        u1x = "0x14c81e3d32a930af141ff28f337e375bd7f2b35d006b2f6ba9a4c9eed7937e2b20d8b251fef776b0d497859510c9fad7"
        u1y = "0x05764cf5fe69554b971c5fe77eb3f3f9b89534547335b84ff02cd3d613bcd5e3037005b9226011a61a70b5bd0f0db570"

      let ecp = toECP2(
        x = hexToFP2(
          # x = x' + iy'
          x = "0x07896efdac56b0f6cbd8c78841676d63fc733b692628687bf25273aa8a107bd8cb53bbdb705b551e239dffe019abd4df",
          y = "0x0bd557eda8d16ab2cb2e71cca4d7b343985064daad04734e07da5cdda26610b59cdc0810a25276467d24b315bf7860e0",
        ),
        y = hexToFP2(
          # y = x'' + iy''
          x = "0x001bdb6290cae9f30f263dd40f014b9f4406c3fbbc5fea47e2ebd45e42332553961eb53a15c09e5e090d7a7122dc6657",
          y = "0x18370459c44e799af8ef31634a683e340e79c3a06f912594d287a443620933b47a2a3e5ce4470539eae50f6d49b8ebd6"
        )
      )
