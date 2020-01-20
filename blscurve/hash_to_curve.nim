# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Hash to Elliptic curve implementation for BLS12-381.
# - IETF Standard Draft: https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04
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

import
  # Status libraries
  nimcrypto/hmac, stew/endians2,
  # Internal
  ./milagro, ./hkdf, ./common

func hashToBaseFP2[T](
                   ctx: var HMAC[T],
                   msg: ptr byte, msgLen: uint,
                   ctr: range[0'i8 .. 2'i8],
                   domainSepTag: ptr byte,
                   domainSepTagLen: uint
                  ): FP2_BLS381 =
  ## Implementation of hash_to_base for the G2 curve of BLS12-381
  ## https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-5.3
  ##
  ## Inputs
  ## - msg + msgLen: the message to hash
  ##   msg[msgLen] should be the null byte 0x00 (i.e there is an extra null-byte)
  ##   This is an exceptional case where a string is required to end by a null-byte.
  ##   This is a cryptographic security requirement.
  ##   The null byte is not taken into account in msgLen.
  ##   Non-empty Nim strings always end by a null-byte and do not require special handling.
  ##   ⚠️: Raw byte-buffers are not null-byte terminated and require
  ##       preprocessing. THis would trigger a buffer-overflow otherwise.
  ## - ctr: 0, 1 or 2.
  ##   Create independant instances of HKDF-Expand (random oracle)
  ##   from the same HKDF-Extract pseudo-random key
  ## - domainSepTag + domainSepTagLen: A domain separation tag (DST)
  ##   that MUST include a protocol identification string
  ##   SHOULD include a protocol version number.
  ##
  ## Outputs
  ## - A point on FP2
  ##
  ## Temporary
  ## - ctx: a HMAC["cryptographic-hash"] context, for example HMAC[sha256].
  #
  # Note: ctr and domainSepTag are known at compile-time
  #       however having them "static" would duplicate/quadruplicate code
  #       with probably negligible performance improvement.

  const
    L_BLS = 64 # ceil((ceil(log2(p)) + k) / 8), where k is the security
               # parameter of the cryptosystem (e.g., k = 128)
    m = 2      # Extension degree of FP2

  var
    e1, e2: BIG_384
    mprime: MDigest[T.bits]
    info: array[5, byte]
    t: array[L_BLS, byte]

  # The input message to HKDF has a null-byte appended to make it
  # indistinguishable to a random oracle. (Spec section 5.1)
  # Non-empty Nim strings have an extra null-byte after their declared length
  # and no extra preprocessing is needed.
  # If the input is a raw-byte buffer instead of a string,
  # it REQUIRES allocation in a buffer
  # with an extra null-byte beyond the declared length.
  assert not msg.isNil
  assert cast[ptr UncheckedArray[byte]](msg)[msgLen+1] == 0x00
  hkdfExtract(ctx, mprime, domainSepTag, domainSepTagLen, msg, msgLen+1)

  info[0] = ord'H'
  info[1] = ord'2'
  info[2] = ord'C'
  info[3] = byte(ctr)

  template loopIter(ei: untyped, i: range[1..m]): untyped {.dirty.} =
    ## for i in 1 .. m
    ## with m = 2 (extension degree of FP2)
    info[4] = byte(i)
    hkdfExpand(ctx, mprime, info[0].addr, info.len.uint, t[0].addr, t.len.uint)
    # debugecho "t: ", t.toHex()
    discard fromBytes(ei, t)
    # TODO: is field element normalization needed?
    #       internally fromBigs calls
    #       FP_BLS381_nres to convert
    #       to "residue form mod Modulus"

  loopIter(e1, 1)
  loopIter(e2, 2)

  result.fromBigs(e1, e2)

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
      c1 {.global.} = neg mul(B, inv(A)) # -B/A -- TODO: can we compute that as -(B * 1/A)
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
    let k40 = hexToFP2(
      "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
      "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"
    )
    let k41 = hexToFP2(
      "0x00",
      "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3"
    )
    let k42 = hexToFP2(
      "0x12",
      "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99"
    )

  let xp2 = sqr(xp)
  let xp3 = mul(xp, xp2)
  {.noSideEffect.}: # TODO overload `+` and `*` for readability
    # xNum = k(1,3) * x'³ + k(1,2) * x'² + k(1,1) * x' + k(1,0)
    let xNum = (
                 k13.mul(xp3)
               ).add(
                 k12.mul(xp2)
               ).add(
                 k11.mul(xp)
               ).add(
                 k10
               )
    # xDen = x'² + k(2,1) * x' + k(2,0)
    let xDen = (
                 xp2
               ).add(
                 k21.mul(xp)
               ).add(
                 k20
               )

    # yNum = k(3,3) * x'³ + k(3,2) * x'² + k(3,1) * x' + k(3,0)
    let yNum = (
                 k33.mul(xp3)
               ).add(
                 k32.mul(xp2)
               ).add(
                 k31.mul(xp)
               ).add(
                 k30
               )
    # yDen = x'³ + k(4,2) * x'2 + k(4,1) * x' + k(4,0)
    let yDen = (
                 xp3
               ).add(
                 k42.mul(xp2)
               ).add(
                 k41.mul(xp)
               ).add(
                 k40
               )

  # TODO - can we divide by multiplying by the inverse
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

func clearCofactor(P: ECP2_BLS381): ECP2_BLS381 =
  ## From any point on the elliptic curve of G2 of BLS12-381
  ## Obtain a point in the G2 subgroup
  ##
  ## Described in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-7
  #
  # Implementations, multiple implementations are possible in decreasing order of speed:
  #
  # - The default, canonical, implementation is h_eff * P
  # - Scott et al, "Fast Hashing to G2 on Pairing-Friendly Curves", https://doi.org/10.1007/978-3-642-03298-1_8
  # - Fuentes-Castaneda et al, "Fast Hashing to G2 on Pairing-Friendly Curves", https://doi.org/10.1007/978-3-642-28496-0_25
  # - Budroni et al, "Hashing to G2 on BLS pairing-friendly curves", https://doi.org/10.1145/3313880.3313884
  # - Wahby et al "Fast and simple constant-time hashing to the BLS12-381 elliptic curve", https://eprint.iacr.org/2019/403
  mulCoFactor(P)

func hashToG2*(message, domainSepTag: string): ECP2_BLS381 =
  ## Hash an arbitrary message to the G2 curve of BLS12-381
  ## The message should have an extra null byte
  # TODO: an API for strings (which are null-terminated)
  #       and an API for raw bytes which needs extra allocation
  # TODO: API should use ptr+len to bytes
  # TODO: handle empty messages in constant-time
  var ctx: HMAC[sha256]
  let
    pmsg = cast[ptr byte](message[0].unsafeAddr)
    msgLen = message.len.uint
    pdst = cast[ptr byte](domainSepTag[0].unsafeAddr)
    dstLen = domainSepTag.len.uint

    u0 = hashToBaseFP2(ctx, pmsg, msgLen, ctr = 0, pdst, dstLen)
    u1 = hashToBaseFP2(ctx, pmsg, msgLen, ctr = 1, pdst, dstLen)
    Q0 = mapToCurveG2(u0)
    Q1 = mapToCurveG2(u1)

  var R = Q0
  R.add(Q1)

  result = clearCofactor(R)

# Unofficial test vectors for hashToG2 primitives
# ----------------------------------------------------------------------

when isMainModule:
  import stew/byteutils, nimcrypto/[sha2, hmac]

  proc hexToBytes(s: string): seq[byte] =
    if s.len != 0: return hexToSeqByte(s)

  template testHashToBaseFP2(id, constants: untyped) =
    # https://github.com/mratsim/py_ecc/pull/1
    proc `test _ id`() =
      # We create a proc to avoid allocating too much globals.
      constants

      let pmsg = if msg.len == 0: nil
                 else: cast[ptr byte](msg[0].unsafeAddr)
      let pdst = cast[ptr byte](dst[0].unsafeAddr)

      var ctx: HMAC[sha256]
      # Important: do we need to include the null byte at the end?
      let pointFP2 = hashToBaseFP2(
        ctx,
        pmsg, msg.len.uint,
        ctr,
        pdst, dst.len.uint
      )
      echo pointFP2

    `test _ id`()

  block: # hashToBaseFP2
    testHashToBaseFP2 1:
      let
        msg = "msg"
        ctr = 0'i8
        dst = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"

      # Expected output after hkdfExpand
      let t = [
        "0x3852c6c62ecd4e04360c24e8ddeac03661b07575a60d6fb7b0a90ce0bb7c7667624fbeea77777e52099dd43356e03192b3d4d27264fd09d0afadda24f48b6f2c",
        "0x099695b4dc8d5dbebc73a9856cc859a3e5317e9a9e0459ee8fc03646bdcfe30125aa434dda228311f25d8c227d5eee289dd6a50897c08397565bc826c5c4113d"
      ]

      # TODO: doAssert the FP2

  # Test vectors for hashToG2
  # ----------------------------------------------------------------------
  # TODO, move to tests/ folder

  template testHashToG2(id, constants: untyped) =
    # https://github.com/mratsim/py_ecc/pull/1
    proc `test _ id`() =
      # We create a proc to avoid allocating too much globals.
      constants

      let pointG2 = hashToG2(msg, dst)
      echo "In projective coordinate (x, y, z)"
      echo pointG2
      echo "In Affine coordinate (x, y)"
      var x, y: FP2_BLS381
      discard ECP2_BLS381_get(x.addr, y.addr, pointG2.unsafeAddr)
      echo "(", $x, ", ", $y, ")"

    `test _ id`()

  block: # hashToBaseFP2
    testHashToG2 1:
      let
        msg = "msg"
        dst = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"

      # Expected output
      let point = (
        # x
        ["0x7896efdac56b0f6cbd8c78841676d63fc733b692628687bf25273aa8a107bd8cb53bbdb705b551e239dffe019abd4df",
         "0xbd557eda8d16ab2cb2e71cca4d7b343985064daad04734e07da5cdda26610b59cdc0810a25276467d24b315bf7860e0"],
        # y
        ["0x1bdb6290cae9f30f263dd40f014b9f4406c3fbbc5fea47e2ebd45e42332553961eb53a15c09e5e090d7a7122dc6657",
         "18370459c44e799af8ef31634a683e340e79c3a06f912594d287a443620933b47a2a3e5ce4470539eae50f6d49b8ebd6"]
      )
