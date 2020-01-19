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

proc toFP2(x, y: uint64): FP2_BLS381 =
  ## Convert a complex tuple x + iy to FP2
  # TODO: the result does not seem to need zero-initialization
  var xBig, yBig: BIG_384

  discard xBig.fromBytes(x.toBytesBE())
  discard yBig.fromBytes(y.toBytesBE())

  result.fromBigs(xBig, yBig)

proc isSquare(a: FP2_BLS381): bool =
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

proc isNeg(a: FP2_BLS381): bool =
  ## Returns the "negative sign" (mod q) of a value
  ## a is negative when a (mod q) > -a (mod q)
  ## https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-4.1.1

  let neg = neg(a)
  result = cmp(a, neg) < 0

func mapToCurveSimpleSWU_G2(u: FP2_BLS381): ECP2_BLS381 =
  ## Implementation of map_to_curve_simple_swu
  ## for the G2 curve of BLS12-381 curve.
  ##
  ## SWU stands for Shallue-van de Woestijne-Ulas mapping
  ## described in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-6.5.2
  ##
  ## Input:
  ## - u, an element of FP2
  ##
  ## Output:
  ## - (x, y), a point on G2

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
    gx1.add(gx1, B)                      # gx1 = g(x1) = x1^3 + A * x1 + B
    let x2 = mul(tv1, x1)                # x2 = Z * u² * x1
    tv2.mul(tv1, tv2)
    let gx2 = mul(gx1, tv2)              # gx2 = (Z * u²)³ * gx1
    let e2 = gx1.isSquare()
    let x = cmov(x2, x1, e2)             # If is_square(gx1), x = x1, else x = x2
    let y2 = cmov(gx2, gx1, e2)          # If is_square(gx1), y2 = gx1, else y2 = gx2
    var y = sqrt(y2)
    let e3 = u.isNeg() == y.isNeg()      # Fix sign of y
    y = cmov(neg y, y, e3)

  let onCurve = bool ECP2_BLS381_set(addr result, unsafeAddr x, unsafeAddr y)
  assert onCurve

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
