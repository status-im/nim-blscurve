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
  nimcrypto/[sha2, hash], stew/endians2,
  # Internal
  ./milagro, ./common

func ceilDiv(a, b: int): int =
  ## ceil division
  ## ceil(a / b)
  (a + b - 1) div b

func dstToDSTprime(dst: string): seq[byte] =
  # Reinterpret a domain separation tag as seq[byte]
  # and append its length.
  # Can be used at compiletime
  for ch in dst:
    result.add byte(ch)
  result.add byte(dst.len)

func expandMessageXMD[B: byte|char, len_in_bytes: static int](
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
  # Note: we require static string for the domain separation tag
  # so that domainSepTagPrime can be constructed without intermediate
  # allocations:
  # - threadsafe
  # - no GC in cryptographic code
  const
    b_in_bytes = H.bits.ceilDiv(8) # b_in_bytes, ceil(b / 8) for b the output size of H in bits.
                                   # For example, for b = 256, b_in_bytes = 32.
    r_in_bytes = H.bsize           # r_in_bytes, the input block size of H, measured in bytes.
                                   # For example, for SHA-256, r_in_bytes = 64.
  static:
    when H is sha256:
      doAssert b_in_bytes == 32, "Expected 32, got " & $b_in_bytes
      doAssert r_in_bytes == 64, "Expected 64, got " & $r_in_bytes

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
  # 10. uniform_bytes = b_1 || ... || b_ell
  # 11. return substr(uniform_bytes, 0, len_in_bytes)

  const ell = len_in_bytes.ceilDiv(b_in_bytes)
  static: doAssert ell <= 255, "Please implement the \"oversized\" part of the Hash-To-Curve spec"

  const dst_prime = dstToDSTprime(domainSepTag)
  static: doAssert dst_prime.len == domainSepTag.len + 1

  const z_pad = default(array[r_in_bytes, byte])
  const l_i_b_str = toBytesBE(uint16(len_in_bytes))

  var ctx: H

  ctx.init()
  let b_0 = block:
    ctx.update z_pad
    if msg.len != 0:
      ctx.update toOpenArray(cast[ptr UncheckedArray[byte]](msg[0].unsafeAddr), 0, msg.len-1)
    ctx.update l_i_b_str
    ctx.update [byte 0]
    ctx.update dst_prime
    ctx.finish()
    # burnMem?

  ctx.init()
  var b_1 = block:
    ctx.update(b_0.data)
    ctx.update([byte 1])
    ctx.update(dst_prime)
    ctx.finish()

  var cur = 0

  template copyFrom[M, N](output: var array[M, byte], bi: array[N, byte], cur: var int) =
    var b_index = 0
    while b_index < bi.len and cur < len_in_bytes:
      output[cur] = bi[b_index]
      inc cur
      inc b_index

  output.copyFrom(b_1.data, cur)

  var b_i{.noinit.}: array[H.bits div 8, byte]

  template strxor(b_i1: var array, b0: array): untyped =
    for i in 0 ..< b_i1.len:
      b_i1[i] = b_i1[i] xor b0[i]

  for i in 2 .. ell:
    ctx.init()
    if i == 2:
      strxor(b_1.data, b_0.data)
      ctx.update(b_1.data)
    else:
      strxor(b_i, b_0.data)
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
        output: var array[count, FP2_BLS12381],
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
  # 2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
  # 3. for i in (0, ..., count - 1):
  # 4.   for j in (0, ..., m - 1):
  # 5.     elm_offset = L * (j + i * m)
  # 6.     tv = substr(uniform_bytes, elm_offset, L)
  # 7.     e_j = OS2IP(tv) mod p
  # 8.   u_i = (e_0, ..., e_(m - 1))
  # 9. return (u_0, ..., u_(count - 1))
  const len_in_bytes = count * m * L_BLS

  var uniform_bytes{.noinit.}: array[len_in_bytes, byte]
  sha256.expandMessageXMD(uniform_bytes, msg, domainSepTag)

  for i in 0 ..< count:
    var e_0{.noinit.}, e_1{.noinit.}: BIG_384
    var de_j{.noinit.}: DBIG_384 # Need a DBIG, L = 64 bytes = 512-bit > 384-bit

    template loopIter(e_j: untyped, j: range[1..m]): untyped {.dirty.} =
      block: ## for j in 0 ..< m
        let elm_offset = L_BLS * (j + i * m)
        template tv: untyped = uniform_bytes.toOpenArray(elm_offset, elm_offset + L_BLS-1)
        discard de_j.fromBytes(tv)
        {.noSideEffect.}:
          BIG_384_dmod(e_j, de_j, FIELD_Modulus)

    loopIter(e_0, 0)
    loopIter(e_1, 1)
    output[i].fromBigs(e_0, e_1)

func toFP2(x, y: uint64): FP2_BLS12381 =
  ## Convert a complex tuple x + iy to FP2
  # TODO: the result does not seem to need zero-initialization
  var xBig, yBig: BIG_384

  discard xBig.fromBytes(x.toBytesBE())
  discard yBig.fromBytes(y.toBytesBE())

  result.fromBigs(xBig, yBig)

func hexToFP2(x, y: string): FP2_BLS12381 =
  ## Convert a complex tuple x + iy to FP2
  # TODO: the result does not seem to need zero-initialization
  var xBig, yBig: BIG_384

  discard xBig.fromHex(x)
  discard yBig.fromHex(y)

  result.fromBigs(xBig, yBig)

func sign0(x: FP2_BLS12381): bool =
  ## Returns the "sign" (mod q^m) of a value
  ## https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-4.1
  ##
  ## Specialized for the quadratic extension field (m == 2)
  # May need further changes? https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/pull/250
  let sign_0 = x.a.parity()
  let zero_0 = x.a.iszilch().int
  let sign_1 = x.b.parity()
  return bool(sign_0 or (zero_0 and sign_1))

func mapToIsoCurveSimpleSWU_G2(u: FP2_BLS12381): tuple[x, y: FP2_BLS12381] =
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
      var one: FP2_BLS12381
      setOne(one)
      one

  {.noSideEffect.}:
    let tv1 = mul(Z, sqr(u))
    var tv2 = sqr(tv1)
    var x1 = add(tv1, tv2)
    x1 = inv(x1)                         # TODO: Spec defines inv0(0) == 0; inv0(x) == x^(q-2)
    let e1 = x1.iszilch()
    x1.add(x1, one)                      # // no norm needed when adding one
    x1.cmov(c2, e1)                      # If (tv1 + tv2) == 0, set x1 = -1 / Z
    x1.mul(x1, c1)                       # x1 = (-B / A) * (1 + (1 / (Z² * u^4 + Z * u²)))
    var gx1 = sqr(x1)
    gx1.add(gx1, A); gx1.norm()
    gx1.mul(gx1, x1)
    gx1.add(gx1, B); gx1.norm()          # gx1 = g(x1) = x1³ + A * x1 + B
    let x2 = mul(tv1, x1)                # x2 = Z * u² * x1
    tv2.mul(tv1, tv2)
    let gx2 = mul(gx1, tv2)              # gx2 = (Z * u²)³ * gx1
    let e2 = gx1.isSquare()
    let x = cmov(x2, x1, e2)             # If is_square(gx1), x = x1, else x = x2
    let y2 = cmov(gx2, gx1, e2)          # If is_square(gx1), y2 = gx1, else y2 = gx2
    var y = sqrt(y2)
    let e3 = u.sign0() == y.sign0()      # Fix sign of y
    y = cmov(neg y, y, e3)

  result.x = x
  result.y = y

func isogeny_map_G2(xp, yp: FP2_BLS12381): ECP2_BLS12381 =
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

  # Note: 32-bit use 29 bits limbs so you can do at most 3 additions before normalizing
  {.noSideEffect.}: # TODO overload `+` and `*` for readability
    # xNum = k(1,3) * x'³ + k(1,2) * x'² + k(1,1) * x' + k(1,0)
    let xNum = block:
      var xNum = k13.mul(xp3)
      xNum.add xNum, k12.mul(xp2)
      xNum.add xNum, k11.mul(xp)
      xNum.add xNum, k10
      norm(xNum)
      xNum

    # xDen = x'² + k(2,1) * x' + k(2,0)
    let xDen = block:
      var xDen = xp2
      xDen.add xDen, k21.mul(xp)
      xDen.add xDen, k20
      norm(xDen)
      xDen

    # yNum = k(3,3) * x'³ + k(3,2) * x'² + k(3,1) * x' + k(3,0)
    let yNum = block:
      var yNum = k33.mul(xp3)
      yNum.add yNum, k32.mul(xp2)
      yNum.add yNum, k31.mul(xp)
      yNum.add yNum, k30
      norm(yNum)
      yNum

    # yDen = x'³ + k(4,2) * x'² + k(4,1) * x' + k(4,0)
    let yDen = block:
      var yDen = xp3
      yDen.add yDen, k42.mul(xp2)
      yDen.add yDen, k41.mul(xp)
      yDen.add yDen, k40
      norm(yDen)
      yDen

  let x = xNum.mul inv(xDen)
  let y = yp.mul yNum.mul inv(yDen)

  let onCurve = bool ECP2_BLS12381_set(addr result, unsafeAddr x, unsafeAddr y)
  assert onCurve

func mapToCurveG2*(u: FP2_BLS12381): ECP2_BLS12381 =
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
  isogeny_map_G2(pointPrime.x, pointPrime.y)

func clearCofactor*(P: var ECP2_BLS12381) =
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
  # We reuse the relevant clearCofactor routines from ``ECP2_BLS12381_mapit``
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

func hashToG2*[B: byte|char](msg: openArray[B],
                            domainSepTag: static string): ECP2_BLS12381 =
  ## Hash an arbitrary message to the G2 curve of BLS12-381
  ## The message should have an extra null byte after its declared length
  # Note: we require static string for the domain separation tag
  # so that domainSepTagPrime in expandMessageXMD
  # can be constructed without intermediate
  # allocations:
  # - threadsafe
  # - no GC in cryptographic code
  var u{.noinit.}: array[2, FP2_BLS12381]

  sha256.hashToFieldFP2(u, msg, domainSepTag)

  result = mapToCurveG2(u[0])
  let Q1 = mapToCurveG2(u[1])

  result.add(Q1)
  result.clearCofactor()

{.pop.} # raises: [Defect]

# T vectors for hashToG2 primitives
# ----------------------------------------------------------------------

when isMainModule:
  import stew/byteutils

  # Test vectors for expandMessageXMD
  # ----------------------------------------------------------------------

  template testExpandMessageXMD(id, constants: untyped) =
    # Section "Expand test vectors {#expand-testvectors}"
    # Revision of Draft 7 - May 26, 2020 - https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/pull/266
    proc `testExpandMessageXMD_sha256 _ id`() =
      # We create a proc to avoid allocating to much globals/
      constants

      var uniform_bytes: array[len_in_bytes, byte]
      sha256.expandMessageXMD(
        uniform_bytes,
        msg,
        "QUUX-V01-CS02-with-expander"
      )

      doAssert uniform_bytes == expectedBytes, ( "\n" &
        "Expected " & toHex(expectedBytes) & "\n" &
        "Computed " & toHex(uniform_bytes)
      )

      echo "Success sha256.expandMessageXMD ", astToStr(id)

    `testExpandMessageXMD_sha256 _ id`()

  testExpandMessageXMD(1):
    let msg = ""
    const expected = "f659819a6473c1835b25ea59e3d38914c98b374f0970b7e4c92181df928fca88"
    const len_in_bytes = expected.len div 2
    const expectedBytes = hexToByteArray[len_in_bytes](expected)

  testExpandMessageXMD(2):
    let msg = "abc"
    const expected = "1c38f7c211ef233367b2420d04798fa4698080a8901021a795a1151775fe4da7"
    const len_in_bytes = expected.len div 2
    const expectedBytes = hexToByteArray[len_in_bytes](expected)

  testExpandMessageXMD(3):
    let msg = "abcdef0123456789"
    const expected = "8f7e7b66791f0da0dbb5ec7c22ec637f79758c0a48170bfb7c4611bd304ece89"
    const len_in_bytes = expected.len div 2
    const expectedBytes = hexToByteArray[len_in_bytes](expected)

  testExpandMessageXMD(4):
    let msg = "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    const expected = "3b8e704fc48336aca4c2a12195b720882f2162a4b7b13a9c350db46f429b771b"
    const len_in_bytes = expected.len div 2
    const expectedBytes = hexToByteArray[len_in_bytes](expected)

  testExpandMessageXMD(5):
    let msg = ""
    const expected = "8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f8" &
                     "9580d217aa79526f1708354a76a402d3569d6a9d19ef3de4d0b991" &
                     "e4f54b9f20dcde9b95a66824cbdf6c1a963a1913d43fd7ac443a02" &
                     "fc5d9d8d77e2071b86ab114a9f34150954a7531da568a1ea8c7608" &
                     "61c0cde2005afc2c114042ee7b5848f5303f0611cf297f"
    const len_in_bytes = expected.len div 2
    const expectedBytes = hexToByteArray[len_in_bytes](expected)

  testExpandMessageXMD(6):
    let msg = "abc"
    const expected = "fe994ec51bdaa821598047b3121c149b364b178606d5e72b" &
                     "fbb713933acc29c186f316baecf7ea22212f2496ef3f785a27e84a" &
                     "40d8b299cec56032763eceeff4c61bd1fe65ed81decafff4a31d01" &
                     "98619c0aa0c6c51fca15520789925e813dcfd318b542f879944127" &
                     "1f4db9ee3b8092a7a2e8d5b75b73e28fb1ab6b4573c192"
    const len_in_bytes = expected.len div 2
    const expectedBytes = hexToByteArray[len_in_bytes](expected)

  testExpandMessageXMD(7):
    let msg = "abcdef0123456789"
    const expected = "c9ec7941811b1e19ce98e21db28d22259354d4d0643e3011" &
                     "75e2f474e030d32694e9dd5520dde93f3600d8edad94e5c3649030" &
                     "88a7228cc9eff685d7eaac50d5a5a8229d083b51de4ccc3733917f" &
                     "4b9535a819b445814890b7029b5de805bf62b33a4dc7e24acdf2c9" &
                     "24e9fe50d55a6b832c8c84c7f82474b34e48c6d43867be"
    const len_in_bytes = expected.len div 2
    const expectedBytes = hexToByteArray[len_in_bytes](expected)

  testExpandMessageXMD(8):
    let msg = "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    const expected = "396962db47f749ec3b5042ce2452b619607f27fd3939ece2" &
                     "746a7614fb83a1d097f554df3927b084e55de92c7871430d6b95c2" &
                     "a13896d8a33bc48587b1f66d21b128a1a8240d5b0c26dfe795a1a8" &
                     "42a0807bb148b77c2ef82ed4b6c9f7fcb732e7f94466c8b51e52bf" &
                     "378fba044a31f5cb44583a892f5969dcd73b3fa128816e"
    const len_in_bytes = expected.len div 2
    const expectedBytes = hexToByteArray[len_in_bytes](expected)

  # Test vectors for HashToG2
  # ----------------------------------------------------------------------

  proc displayECP2Coord(name: string, point: ECP2_BLS12381) =
    echo "  --"
    echo "  ", name, ':'
    # echo "    In jacobian projective coordinates (x, y, z)"
    # echo "      ", point
    echo "    In affine coordinate (x, y)"
    var x, y: FP2_BLS12381
    discard ECP2_BLS12381_get(x.addr, y.addr, point.unsafeAddr)
    echo "      (", $x, ", ", $y, ")"

  proc toECP2(x, y: FP2_BLS12381): ECP2_BLS12381 =
    ## Create a point (x, y) on the G2 curve
    let onCurve = bool ECP2_BLS12381_set(addr result, unsafeAddr x, unsafeAddr y)
    doAssert onCurve, "The coordinates (x, y) are not on the G2 curve"


  template testHashToG2(id, constants: untyped) =
    # Sources:
    # 1. Revision of Draft 7 - May 22, 2020 - with protocol name
    #    in test vectors: https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/pull/255
    # 2. Draft 7, section G.10.1 https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#appendix-G.10.1

    proc `hashToG2Proxy _ id`() =
      # We recreate hashToG2 so that we can check
      # each step in a fine grained manner
      constants

      var u{.noinit.}: array[2, FP2_BLS12381]

      sha256.hashToFieldFP2(u, msg, domainSepTag)

      let Q0 = mapToCurveG2(u[0])
      let Q1 = mapToCurveG2(u[1])

      var R = Q0
      R.add(Q1)
      var P = R
      P.clearCofactor()

      if P != P_ref:
        echo "Test failed for input:"
        echo "  suite:  BLS12381G2_XMD:SHA~256_SSWU_RO_"
        echo "  DST:    ", domainSepTag
        echo "  msg:    \"", msg, '\"'
        echo "  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        echo "  u0_cpt: ", u[0]
        echo "  u0_ref: ", u0_ref
        echo "  ok?:    ", u[0] == u0_ref
        echo "  u1_cpt: ", u[1]
        echo "  u1_ref: ", u1_ref
        echo "  ok?:    ", u[1] == u1_ref
        echo "  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        displayECP2Coord("Q0_cpt", Q0)
        displayECP2Coord("Q0_ref", Q0_ref)
        echo "  ok?:    ", Q0 == Q0_ref
        displayECP2Coord("Q1_cpt", Q1)
        displayECP2Coord("Q1_ref", Q1_ref)
        echo "  ok?:    ", Q1 == Q1_ref
        echo "  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        displayECP2Coord("R_cpt ", R)
        echo "  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        displayECP2Coord("P_cpt ", P)
        displayECP2Coord("P_ref ", P_ref)
        echo "  ok?:    ", P == P_ref
        echo "Exiting with error"
        quit 1
      echo "Success HashToG2 - ", astToStr(id)
    `hashToG2Proxy _ id`()

  block:
    testHashToG2(1):
      const domainSepTag = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"
      let msg = ""

      const
        Px_re  = "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d693352" &
                 "66f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a"
        Px_im  = "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab" &
                 "379ba13dff5bf5dd71b72418717047f5b0f37da03d"
        Py_re  = "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11" &
                 "062ee75ec076daf2d4bc358c4b190c0c98064fdd92"
        Py_im  = "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259d" &
                 "dc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6"
        u0_re  = "03dbc2cce174e91ba93cbb08f26b917f98194a2ea08d1cce75b2b9" &
                 "cc9f21689d80bd79b594a613d0a68eb807dfdc1cf8"
        u0_im  = "05a2acec64114845711a54199ea339abd125ba38253b70a92c876d" &
                 "f10598bd1986b739cad67961eb94f7076511b3b39a"
        u1_re  = "02f99798e8a5acdeed60d7e18e9120521ba1f47ec090984662846b" &
                 "c825de191b5b7641148c0dbc237726a334473eee94"
        u1_im  = "145a81e418d4010cc027a68f14391b30074e89e60ee7a22f87217b" &
                 "2f6eb0c4b94c9115b436e6fa4607e95a98de30a435"
        q0x_re = "019ad3fc9c72425a998d7ab1ea0e646a1f6093444fc6965f1cad5a" &
                 "3195a7b1e099c050d57f45e3fa191cc6d75ed7458c"
        q0x_im = "171c88b0b0efb5eb2b88913a9e74fe111a4f68867b59db252ce586" &
                 "8af4d1254bfab77ebde5d61cd1a86fb2fe4a5a1c1d"
        q0y_re = "0ba10604e62bdd9eeeb4156652066167b72c8d743b050fb4c1016c" &
                 "31b505129374f76e03fa127d6a156213576910fef3"
        q0y_im = "0eb22c7a543d3d376e9716a49b72e79a89c9bfe9feee8533ed931c" &
                 "bb5373dde1fbcd7411d8052e02693654f71e15410a"
        q1x_re = "113d2b9cd4bd98aee53470b27abc658d91b47a78a51584f3d4b950" &
                 "677cfb8a3e99c24222c406128c91296ef6b45608be"
        q1x_im = "13855912321c5cb793e9d1e88f6f8d342d49c0b0dbac613ee9e17e" &
                 "3c0b3c97dfbb5a49cc3fb45102fdbaf65e0efe2632"
        q1y_re = "0fd3def0b7574a1d801be44fde617162aa2e89da47f464317d9bb5" &
                 "abc3a7071763ce74180883ad7ad9a723a9afafcdca"
        q1y_im = "056f617902b3c0d0f78a9a8cbda43a26b65f602f8786540b9469b0" &
                 "60db7b38417915b413ca65f875c130bebfaa59790c"

      let
        u0_ref = hexToFP2(u0_re, u0_im)
        u1_ref = hexToFP2(u1_re, u1_im)
        Q0_ref = toECP2(hexToFP2(q0x_re, q0x_im), hexToFP2(q0y_re, q0y_im))
        Q1_ref = toECP2(hexToFP2(q1x_re, q1x_im), hexToFP2(q1y_re, q1y_im))
        P_ref = toECP2(hexToFP2(Px_re, Px_im), hexToFP2(Py_re, Py_im))

  block:
    testHashToG2(2):
      const domainSepTag = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"
      let msg = "abc"

      const
        Px_re  = "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a21" &
                 "0245129dbec7780ccc7954725f4168aff2787776e6"
        Px_im  = "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9" &
                 "eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8"
        Py_re  = "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea0" &
                 "5c4cfe244aeb197642555a0645fb87bf7466b2ba48"
        Py_im  = "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e" &
                 "9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16"
        u0_re  = "15f7c0aa8f6b296ab5ff9c2c7581ade64f4ee6f1bf18f55179ff44" &
                 "a2cf355fa53dd2a2158c5ecb17d7c52f63e7195771"
        u0_im  = "01c8067bf4c0ba709aa8b9abc3d1cef589a4758e09ef53732d670f" &
                 "d8739a7274e111ba2fcaa71b3d33df2a3a0c8529dd"
        u1_re  = "187111d5e088b6b9acfdfad078c4dacf72dcd17ca17c82be35e79f" &
                 "8c372a693f60a033b461d81b025864a0ad051a06e4"
        u1_im  = "08b852331c96ed983e497ebc6dee9b75e373d923b729194af8e72a" &
                 "051ea586f3538a6ebb1e80881a082fa2b24df9f566"
        q0x_re = "12b2e525281b5f4d2276954e84ac4f42cf4e13b6ac4228624e1776" &
                 "0faf94ce5706d53f0ca1952f1c5ef75239aeed55ad"
        q0x_im = "05d8a724db78e570e34100c0bc4a5fa84ad5839359b40398151f37" &
                 "cff5a51de945c563463c9efbdda569850ee5a53e77"
        q0y_re = "02eacdc556d0bdb5d18d22f23dcb086dd106cad713777c7e640794" &
                 "3edbe0b3d1efe391eedf11e977fac55f9b94f2489c"
        q0y_im = "04bbe48bfd5814648d0b9e30f0717b34015d45a861425fabc1ee06" &
                 "fdfce36384ae2c808185e693ae97dcde118f34de41"
        q1x_re = "19f18cc5ec0c2f055e47c802acc3b0e40c337256a208001dde14b2" &
                 "5afced146f37ea3d3ce16834c78175b3ed61f3c537"
        q1x_im = "15b0dadc256a258b4c68ea43605dffa6d312eef215c19e6474b3e1" &
                 "01d33b661dfee43b51abbf96fee68fc6043ac56a58"
        q1y_re = "05e47c1781286e61c7ade887512bd9c2cb9f640d3be9cf87ea0bad" &
                 "24bd0ebfe946497b48a581ab6c7d4ca74b5147287f"
        q1y_im = "19f98db2f4a1fcdf56a9ced7b320ea9deecf57c8e59236b0dc21f6" &
                 "ee7229aa9705ce9ac7fe7a31c72edca0d92370c096"

      let
        u0_ref = hexToFP2(u0_re, u0_im)
        u1_ref = hexToFP2(u1_re, u1_im)
        Q0_ref = toECP2(hexToFP2(q0x_re, q0x_im), hexToFP2(q0y_re, q0y_im))
        Q1_ref = toECP2(hexToFP2(q1x_re, q1x_im), hexToFP2(q1y_re, q1y_im))
        P_ref = toECP2(hexToFP2(Px_re, Px_im), hexToFP2(Py_re, Py_im))

  block:
    testHashToG2(3):
      const domainSepTag = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"
      let msg = "abcdef0123456789"

      const
        Px_re  = "121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4" &
                 "c0028add35aea8bb83d53c08cfc007c1e005723cd0"
        Px_im  = "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cb" &
                 "ba169fb3968288b3fafb265f9ebd380512a71c3f2c"
        Py_re  = "05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf13" &
                 "56a6acf17574518acb506e435b639353c2e14827c8"
        Py_im  = "0bb5e7572275c567462d91807de765611490205a941a5a6af3b169" &
                 "1bfe596c31225d3aabdf15faff860cb4ef17c7c3be"
        u0_re  = "0313d9325081b415bfd4e5364efaef392ecf69b087496973b22930" &
                 "3e1816d2080971470f7da112c4eb43053130b785e1"
        u0_im  = "062f84cb21ed89406890c051a0e8b9cf6c575cf6e8e18ecf63ba86" &
                 "826b0ae02548d83b483b79e48512b82a6c0686df8f"
        u1_re  = "1739123845406baa7be5c5dc74492051b6d42504de008c635f3535" &
                 "bb831d478a341420e67dcc7b46b2e8cba5379cca97"
        u1_im  = "01897665d9cb5db16a27657760bbea7951f67ad68f8d55f7113f24" &
                 "ba6ddd82caef240a9bfa627972279974894701d975"
        q0x_re = "0f48f1ea1318ddb713697708f7327781fb39718971d72a9245b973" &
                 "1faaca4dbaa7cca433d6c434a820c28b18e20ea208"
        q0x_im = "06051467c8f85da5ba2540974758f7a1e0239a5981de441fdd8768" &
                 "0a995649c211054869c50edbac1f3a86c561ba3162"
        q0y_re = "168b3d6df80069dbbedb714d41b32961ad064c227355e1ce5fac8e" &
                 "105de5e49d77f0c64867f3834848f152497eb76333"
        q0y_im = "134e0e8331cee8cb12f9c2d0742714ed9eee78a84d634c9a95f6a7" &
                 "391b37125ed48bfc6e90bf3546e99930ff67cc97bc"
        q1x_re = "004fd03968cd1c99a0dd84551f44c206c84dcbdb78076c5bfee24e" &
                 "89a92c8508b52b88b68a92258403cbe1ea2da3495f"
        q1x_im = "1674338ea298281b636b2eb0fe593008d03171195fd6dcd4531e8a" &
                 "1ed1f02a72da238a17a635de307d7d24aa2d969a47"
        q1y_re = "0dc7fa13fff6b12558419e0a1e94bfc3cfaf67238009991c5f24ee" &
                 "94b632c3d09e27eca329989aee348a67b50d5e236c"
        q1y_im = "169585e164c131103d85324f2d7747b23b91d66ae5d947c449c819" &
                 "4a347969fc6bbd967729768da485ba71868df8aed2"

      let
        u0_ref = hexToFP2(u0_re, u0_im)
        u1_ref = hexToFP2(u1_re, u1_im)
        Q0_ref = toECP2(hexToFP2(q0x_re, q0x_im), hexToFP2(q0y_re, q0y_im))
        Q1_ref = toECP2(hexToFP2(q1x_re, q1x_im), hexToFP2(q1y_re, q1y_im))
        P_ref = toECP2(hexToFP2(Px_re, Px_im), hexToFP2(Py_re, Py_im))


  block:
    testHashToG2(4):
      const domainSepTag = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"
      let msg = "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

      const
        Px_re  = "01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64f" &
                 "d24557c2f4b18ecfc5663e54ae16a84f5ab7f62534"
        Px_im  = "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce" &
                 "4a34131d71f7a73e95fee3f812aea3de78b4d01569"
        Py_re  = "0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9" &
                 "db90d2b9da6cbabf48adc1adf59a1a28344e79d57e"
        Py_im  = "03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a66" &
                 "0a9b3994249ae4e63fac38b23da0c398689ee2ab52"
        u0_re  = "190b513da3e66fc9a3587b78c76d1d132b1152174d0b83e3c11140" &
                 "66392579a45824c5fa17649ab89299ddd4bda54935"
        u0_im  = "12ab625b0fe0ebd1367fe9fac57bb1168891846039b4216b9d9400" &
                 "7b674de2d79126870e88aeef54b2ec717a887dcf39"
        u1_re  = "0e6a42010cf435fb5bacc156a585e1ea3294cc81d0ceb81924d950" &
                 "40298380b164f702275892cedd81b62de3aba3f6b5"
        u1_im  = "117d9a0defc57a33ed208428cb84e54c85a6840e7648480ae42883" &
                 "8989d25d97a0af8e3255be62b25c2a85630d2dddd8"
        q0x_re = "17cadf8d04a1a170f8347d42856526a24cc466cb2ddfd506cff011" &
                 "91666b7f944e31244d662c904de5440516a2b09004"
        q0x_im = "0d13ba91f2a8b0051cf3279ea0ee63a9f19bc9cb8bfcc7d78b3cbd" &
                 "8cc4fc43ba726774b28038213acf2b0095391c523e"
        q0y_re = "17ef19497d6d9246fa94d35575c0f8d06ee02f21a284dbeaa78768" &
                 "cb1e25abd564e3381de87bda26acd04f41181610c5"
        q0y_im = "12c3c913ba4ed03c24f0721a81a6be7430f2971ffca8fd1729aafe" &
                 "496bb725807531b44b34b59b3ae5495e5a2dcbd5c8"
        q1x_re = "16ec57b7fe04c71dfe34fb5ad84dbce5a2dbbd6ee085f1d8cd17f4" &
                 "5e8868976fc3c51ad9eeda682c7869024d24579bfd"
        q1x_im = "13103f7aace1ae1420d208a537f7d3a9679c287208026e4e3439ab" &
                 "8cd534c12856284d95e27f5e1f33eec2ce656533b0"
        q1y_re = "0958b2c4c2c10fcef5a6c59b9e92c4a67b0fae3e2e0f1b6b5edad9" &
                 "c940b8f3524ba9ebbc3f2ceb3cfe377655b3163bd7"
        q1y_im = "0ccb594ed8bd14ca64ed9cb4e0aba221be540f25dd0d6ba15a4a4b" &
                 "e5d67bcf35df7853b2d8dad3ba245f1ea3697f66aa"

      let
        u0_ref = hexToFP2(u0_re, u0_im)
        u1_ref = hexToFP2(u1_re, u1_im)
        Q0_ref = toECP2(hexToFP2(q0x_re, q0x_im), hexToFP2(q0y_re, q0y_im))
        Q1_ref = toECP2(hexToFP2(q1x_re, q1x_im), hexToFP2(q1y_re, q1y_im))
        P_ref = toECP2(hexToFP2(Px_re, Px_im), hexToFP2(Py_re, Py_im))

  block:
    testHashToG2(5):
      const domainSepTag = "BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN"
      let msg = ""

      const
        Px_re  = "0a650bd36ae7455cb3fe5d8bb1310594551456f5c6593aec9ee0c0" &
                 "3d2f6cb693bd2c5e99d4e23cbaec767609314f51d3"
        Px_im  = "0fbdae26f9f9586a46d4b0b70390d09064ef2afe5c99348438a3c7" &
                 "d9756471e015cb534204c1b6824617a85024c772dc"
        Py_re  = "0d8d49e7737d8f9fc5cef7c4b8817633103faf2613016cb86a1f3f" &
                 "c29968fe2413e232d9208d2d74a89bf7a48ac36f83"
        Py_im  = "02e5cf8f9b7348428cc9e66b9a9b36fe45ba0b0a146290c3a68d92" &
                 "895b1af0e1f2d9f889fb412670ae8478d8abd4c5aa"
        u0_re  = "0ae8ca9aed945924c3a12f3b6f419cac381bae8f16044ab6c66b41" &
                 "999e4bd0ea169b44f2fce3634a0ddea05b9186c6b2"
        u0_im  = "1134506e471554affe377f908c29fc7cd7d247b3a14f9e092b9f4c" &
                 "5b02577939ce01bd6b43d9d59d9a994e9fb5fb5096"
        u1_re  = "0b28b14113885b1d8ad08f5da9111add00d8c496fb3d5d7b5d3b65" &
                 "58a058e9e62cd02dafa7a95f968cb3063f09fc0e21"
        u1_im  = "03378e456f437ce445b6bc95121566d85b1b3b8ca057064fe7a8a1" &
                 "aad7e8a6e9f886cfb1704ad712e9042f4f002f4bd1"
        q0x_re = "090f7997311a1d4ec54520f81046063f4e9e7a64570133dc41c360" &
                 "0ade2a4d21aae59714cf290f95f90a98b658f5b64a"
        q0x_im = "08427a6a0dc88a36698823d07ab25d11f95a9508cb5bb1ad2bd57b" &
                 "c02b5efb8c7b1da66ed02b0f915002446e24fd5d38"
        q0y_re = "10e03a54fd5ff7a0a69543aeeef42e22cb589e0b33455943cf84f0" &
                 "c5b28e93fe17c0bbba2fafb10aea29b28705eec303"
        q0y_im = "053b939496e87877fb1569c911bf618056396fac2458757da71cd8" &
                 "3fa152239d605c6a4e4e847295080ea3874f84a832"
        q1x_re = "0df5643a19f8de7e8e45575551cfb8909f4a75722ec8fbc43cb8df" &
                 "284cdde9e2c61ea0c6116bdd86d84063c96fc7dc7f"
        q1x_im = "1241a410598f1d57907850699a694720712feddb916f343db08f2c" &
                 "18481df46cbdf7afe8eaf214127e427736ea281c5b"
        q1y_re = "0ad66ed30cb6f55a83feed4b12c141bd41f593292403127b07e1bc" &
                 "6dabacd8ea53f8a322b5d4080e4393184c713865fa"
        q1y_im = "0c4e6fb11ad2fe3a081a399df36094465aafb232f7564f4d35abb0" &
                 "092ef9ee855bcfdac2e6775cd7d383241f13ed856a"

      let
        u0_ref = hexToFP2(u0_re, u0_im)
        u1_ref = hexToFP2(u1_re, u1_im)
        Q0_ref = toECP2(hexToFP2(q0x_re, q0x_im), hexToFP2(q0y_re, q0y_im))
        Q1_ref = toECP2(hexToFP2(q1x_re, q1x_im), hexToFP2(q1y_re, q1y_im))
        P_ref = toECP2(hexToFP2(Px_re, Px_im), hexToFP2(Py_re, Py_im))

  block:
    testHashToG2(6):
      const domainSepTag = "BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN"
      let msg = "abc"

      const
        Px_re  = "1953ce6d4267939c7360756d9cca8eb34aac4633ef35369a7dc249" &
                 "445069888e7d1b3f9d2e75fbd468fbcbba7110ea02"
        Px_im  = "03578447618463deb106b60e609c6f7cc446dc6035f84a72801ba1" &
                 "7c94cd800583b493b948eff0033f09086fdd7f6175"
        Py_re  = "0882ab045b8fe4d7d557ebb59a63a35ac9f3d312581b509af0f8ea" &
                 "a2960cbc5e1e36bb969b6e22980b5cbdd0787fcf4e"
        Py_im  = "0184d26779ae9d4670aca9b267dbd4d3b30443ad05b8546d36a195" &
                 "686e1ccc3a59194aea05ed5bce7c3144a29ec047c4"
        u0_re  = "0a7d239c9bdb41ed2ad810820a8b4f0703f60cf5833440cd684e38" &
                 "6e235b0f092da91adbaa69562b911ebd3f820655f2"
        u0_im  = "16302b56f5a9f538c7168cd5194957903b82be6749171f8de112c8" &
                 "bd3360ca24847d0567d6e42eae0c43a7fd8530b378"
        u1_re  = "0a1cb4196dec71b1f704f3533cdf27f247e3ea175ddcc1ca6df0f4" &
                 "5c587eb77efc6c493848f4df98e24a32753dfcf96b"
        u1_im  = "07aac42db7f3dfbc5146c70ca0ac6157893abf4e2162e303510e0c" &
                 "efb8d024c24080b9c2a9896f6c03ffe680fc18b788"
        q0x_re = "0c292ac371849207564e7b8f4edf47dc4b4d7a618dbacf6a322dc7" &
                 "32f014cc2a22049eb69de11657c301cb4202b98541"
        q0x_im = "0f37118e477c16005cae8f639e54119ff796eafe80461bf39ecce5" &
                 "c0192b93075febc80d4f73f9e0893adafa17b13b45"
        q0y_re = "15853304d7fd9f47df2ef6c4bd1fb0b3500386b23d1acc530be0c1" &
                 "4e027f15b0aa83856d82edb723f3d857358ecffb80"
        q0y_im = "0626fcfc6b3d8460df7ed2aeca6449cf6701dc7ff51c143ed20054" &
                 "ecf18732f4c5985455864c79a4065b13e26ecccf9f"
        q1x_re = "0bce3e2dd15f6acf55cce0e3a4cde190a6d45434a8b0ba7cf79ff3" &
                 "7f737ed90dbfd2988a257db65e10e684e5876b50db"
        q1x_im = "19c1ad3eb0abb3590087d706eb155a4cd166484e82cdccb2465ce1" &
                 "93b15a27d919aaa37d1824a9a9d87f31fefca1baee"
        q1y_re = "110c9643a8dfd00123bb9e6a956426f26bedb0d430130026ce49b8" &
                 "62431e80f5e306850239c857474f564915fc9a4ba6"
        q1y_im = "1748ca13032a2c262295863897a15cd9a7e0baf003336bec6fc6e4" &
                 "0b982d866fe3250619fdd2ceadb49fab8055f47e65"

      let
        u0_ref = hexToFP2(u0_re, u0_im)
        u1_ref = hexToFP2(u1_re, u1_im)
        Q0_ref = toECP2(hexToFP2(q0x_re, q0x_im), hexToFP2(q0y_re, q0y_im))
        Q1_ref = toECP2(hexToFP2(q1x_re, q1x_im), hexToFP2(q1y_re, q1y_im))
        P_ref = toECP2(hexToFP2(Px_re, Px_im), hexToFP2(Py_re, Py_im))

  block:
    testHashToG2(7):
      const domainSepTag = "BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN"
      let msg = "abcdef0123456789"

      const
        Px_re  = "17b461fc3b96a30c2408958cbfa5f5927b6063a8ad199d5ebf2d7c" &
                 "deffa9c20c85487204804fab53f950b2f87db365aa"
        Px_im  = "195fad48982e186ce3c5c82133aefc9b26d55979b6f530992a8849" &
                 "d4263ec5d57f7a181553c8799bcc83da44847bdc8d"
        Py_re  = "174a3473a3af2d0302b9065e895ca4adba4ece6ce0b41148ba5970" &
                 "01abb152f852dd9a96fb45c9de0a43d944746f833e"
        Py_im  = "005cdf3d984e3391e7e969276fb4bc02323c5924a4449af167030d" &
                 "855acc2600cf3d4fab025432c6d868c79571a95bef"
        u0_re  = "0e17df0242a3dd0e7454a4b580cafdc956650736b45181b329ca89" &
                 "ee2348570a1d7a221554c7122b91e6e3c3525d396d"
        u0_im  = "0298e9fa0ff37440cd2862e91c0a27fed05087247acf79232f1a4e" &
                 "b7cf8f65997a92319a8cbd00f7b73ee9e82241eade"
        u1_re  = "1200056764f11beacdb6009acaf823e100da27b4bfe45e94097a52" &
                 "c1fed615b32dbc5503f964ab5277a7c30d9a2bf0de"
        u1_im  = "0d1d7feb418f29dbf4d4459c839dd33f904d4292d016f701b35e4a" &
                 "7611798c83de1b7deb1c6c1521e9142cc36a7d0579"
        q0x_re = "1552566a422494f9edd07e21ee59067ecf031f333b3961b710fac1" &
                 "245fd003552c294ac47ef982432f0f1e1e9d07c4b6"
        q0x_im = "115a9de418d20ce3105eaa2db025d183cc679327c6d6a229960d53" &
                 "6b9fce33d3242f9819680a9200265ec2dd02b44b19"
        q0y_re = "0cef664ee9270354c3bc06d1e0570e4d6663cc528711afca101189" &
                 "55990126f87917c87f7b9c4cf73aaf05c1b5875c6f"
        q0y_im = "0b136f41d233ea420bc3658c4156f717fb190775d3690d139c0923" &
                 "c231e44af54d780119b8edf16038208b63feb1f3ee"
        q1x_re = "0332d5027c68f38ca78c6c63c013178fb58b31283a6135f6bf5629" &
                 "d18c76144accfd96905f51a49284f4ef622dfec003"
        q1x_im = "04865f680c5f2203de00f95dd6652c9b3dc0d36361ee0df16a39a8" &
                 "6d5f7cfc8df3674f3c3fddde88fb027353eac1a3dc"
        q1y_re = "1651e6cc8af2241989a9006dd59a9cd41fc1bbc3a7f9e32875889a" &
                 "e54913b8398dfa106aff43ff1cfa9019141d9ad565"
        q1y_im = "09324bdbfedfb886899a7961f7827702743ef550f548bb89ab15d4" &
                 "b24c7c086196891fc300e3e39c21aec0257543a3fd"

      let
        u0_ref = hexToFP2(u0_re, u0_im)
        u1_ref = hexToFP2(u1_re, u1_im)
        Q0_ref = toECP2(hexToFP2(q0x_re, q0x_im), hexToFP2(q0y_re, q0y_im))
        Q1_ref = toECP2(hexToFP2(q1x_re, q1x_im), hexToFP2(q1y_re, q1y_im))
        P_ref = toECP2(hexToFP2(Px_re, Px_im), hexToFP2(Py_re, Py_im))


  block:
    testHashToG2(8):
      const domainSepTag = "BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN"
      let msg = "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

      const
        Px_re  = "0a162306f3b0f2bb326f0c4fb0e1fea020019c3af796dcd1d7264f" &
                 "50ddae94cacf3cade74603834d44b9ab3d5d0a6c98"
        Px_im  = "123b6bd9feeba26dd4ad00f8bfda2718c9700dc093ea5287d77118" &
                 "44644eb981848316d3f3f57d5d3a652c6cdc816aca"
        Py_re  = "15c1d4f1a685bb63ee67ca1fd96155e3d091e852a684b78d085fd3" &
                 "4f6091e5249ddddbdcf2e7ec82ce6c04c63647eeb7"
        Py_im  = "05483f3b96d9252dd4fc0868344dfaf3c9d145e3387db23fa8e449" &
                 "304fab6a7b6ec9c15f05c0a1ea66ff0efcc03e001a"
        u0_re  = "0ca92554c8c45581eac2eed7ec2db1fe757af0a2803dc8e6318060" &
                 "0eed2516f64b1c0d850c72a75c417f58723815795b"
        u0_im  = "12ef692f69b1d61854b80e071c7fd751b19da2c194ba0fbee9e684" &
                 "54073dd3693e2c56852938aa1b090991018ff15a94"
        u1_re  = "11043d352059287fe7424285da213d4cc414df4d5592ee25075030" &
                 "88b3f89220697753ea8cd47fa13c9a15dbfb0ef20c"
        u1_im  = "110efeacfff2801024c019cee7adbc3d8144c3b73c548ad8f0759c" &
                 "4976e0b3070293056f884dc0a1b3728546dddc6bcb"
        q0x_re = "089b04f318946ce75b5b8c98607041488005ed412a4a99e7106b34" &
                 "0427d35682036cecc076827e700e47c17f65ee3f09"
        q0x_im = "03bef411c75f97147673952b19ee293e28df019be2fdecf5db09af" &
                 "b7caad4a5e984750b19c2007b50ae0b26f83088e8b"
        q0y_re = "18b1ef96738c5df727e1fa2098178fe371751c0c169af30bdb95be" &
                 "22a0ecbf0a75c0e6c63e4a32f241250f877859c086"
        q0y_im = "0d04c624db798ca46a352637fa76516c83a5d98e147a25f629fb1e" &
                 "02a9a453970e42d835ba765bd7d94a4a3f9f50e4a1"
        q1x_re = "121b1257fbd3dda5f478b5de6aee2ca88780248c59afad1a9c9c9d" &
                 "b5d03752792270cecc7cc676a1b91ee898b7f76977"
        q1x_im = "17eadb5c134a1cc0305ad5d99f6e2a1cd906a2fdac318d4356527c" &
                 "70fc94242ddb664486c814ebd5959a2cf4225a783a"
        q1y_re = "00f0793bcfaf12e5d23fdd4173f7539e3cf182a0f5a1c98b488f59" &
                 "daca5ecf7b694912a93f6b81498a5c2282c09ee63f"
        q1y_im = "081adf3c45b42c35fdb678c8bdec1d8c12f9d5a30b22cf52c1afc9" &
                 "67d6ddc82fdae0673f76a5186a84f3602c7a22f6b8"

      let
        u0_ref = hexToFP2(u0_re, u0_im)
        u1_ref = hexToFP2(u1_re, u1_im)
        Q0_ref = toECP2(hexToFP2(q0x_re, q0x_im), hexToFP2(q0y_re, q0y_im))
        Q1_ref = toECP2(hexToFP2(q1x_re, q1x_im), hexToFP2(q1y_re, q1y_im))
        P_ref = toECP2(hexToFP2(Px_re, Px_im), hexToFP2(Py_re, Py_im))
