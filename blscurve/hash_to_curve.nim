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

# TODO: clarify the meaning of string / octet string / bit string
#       the EF implementation appends a 0x00 byte to messages
#       that does not exist in the IETF spec.

# hash_to_curve
# ----------------------------------------------------------------------
# Section 3 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-3
#
# This section presents a general framework for encoding bit strings to
# points on an elliptic curve.  To construct these encodings, we rely
# on three basic functions:
#
# o  The function hash_to_base, {0, 1}^* x {0, 1, 2} -> F, hashes
#    arbitrary-length bit strings to elements of a finite field; its
#    implementation is defined in Section 5.
#
# o  The function map_to_curve, F -> E, calculates a point on the
#    elliptic curve E from an element of the finite field F over which
#    E is defined.  Section 6 describes mappings for a range of curve
#    families.
#
# o  The function clear_cofactor, E -> G, sends any point on the curve
#    E to the subgroup G of E.  Section 7 describes methods to perform
#    this operation.
#
# [...] (Overview of encode_to_curve)
#
# Random oracle encoding (hash_to_curve).
#   This function encodes bitstrings to points in G.
#   The distribution of the output is
#   indistinguishable from uniformly random in G provided that
#   map_to_curve is "well distributed" ([FFSTV13], Def. 1).  All of
#   the map_to_curve functions defined in Section 6 meet this
#   requirement.
#
#   hash_to_curve(alpha)
#
#   Input: alpha, an arbitrary-length bit string.
#   Output: P, a point in G.
#
#   Steps:
#   1. u0 = hash_to_base(alpha, 0)
#   2. u1 = hash_to_base(alpha, 1)
#   3. Q0 = map_to_curve(u0)
#   4. Q1 = map_to_curve(u1)
#   5. R = Q0 + Q1      // point addition
#   6. P = clear_cofactor(R)
#   7. return P
#
#   Instances of these functions are given in Section 8, which defines a
#   list of suites that specify a full set of parameters matching
#   elliptic curves and algorithms.

# hash_to_base
# ----------------------------------------------------------------------
# Section 5.3 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-5.3
#
# The following procedure implements hash_to_base.
#
# hash_to_base(msg, ctr)
#
# Parameters:
# - DST, a domain separation tag (see discussion above).
# - H, a cryptographic hash function.
# - F, a finite field of characteristic p and order q = p^m.
# - L = ceil((ceil(log2(p)) + k) / 8), where k is the security
#   parameter of the cryptosystem (e.g., k = 128).
# - HKDF-Extract and HKDF-Expand are as defined in RFC5869,
#   instantiated with the hash function H.
#
# Inputs:
# - msg is the message to hash.
# - ctr is 0, 1, or 2.
#   This is used to efficiently create independent
#   instances of hash_to_base (see discussion above).
#
# Output:
# - u, an element in F.
#
# Steps:
# 1. m' = HKDF-Extract(DST, msg)
# 2. for i in (1, ..., m):
# 3.   info = "H2C" || I2OSP(ctr, 1) || I2OSP(i, 1)
# 4.   t = HKDF-Expand(m', info, L)
# 5.   e_i = OS2IP(t) mod p
# 6. return u = (e_1, ..., e_m)
#
# Note:
#   I2OSP and OS2IP: These primitives are used to convert an octet string to
#   and from a non-negative integer as described in RFC8017.
#   https://tools.ietf.org/html/rfc8017#section-4
#
#   In summary those are bigEndian <-> integer conversion with signatures
#   - proc I2OSP(n: Natural, resultLen: Natural): string
#   - proc OS2IP(s: string): Natural

# Implementation
# ----------------------------------------------------------------------

import
  # Status libraries
  nimcrypto/hmac,
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

  # TODO: assert ending by 0x00 byte?
  hkdfExtract(ctx, mprime, domainSepTag, domainSepTagLen, msg, msgLen)

  info[0] = ord'H'
  info[1] = ord'2'
  info[2] = ord'C'
  info[3] = byte(ctr)

  template loopIter(ei: untyped, i: range[1..m]): untyped {.dirty.} =
    ## for i in 1 .. m
    ## with m = 2 (extension degree of FP2)
    info[4] = byte(i)
    hkdfExpand(ctx, mprime, info[0].addr, info.len.uint, t[0].addr, t.len.uint)
    discard fromBytes(ei, t)

  loopIter(e1, 1)
  loopIter(e2, 2)

  result.fromBigs(e1, e2)

# Unofficial test vectors for hashToG2 primitives
# ----------------------------------------------------------------------
# https://github.com/mratsim/py_ecc/pull/1

when isMainModule:
  import stew/byteutils, nimcrypto/[sha2, hmac]

  proc hexToBytes(s: string): seq[byte] =
    if s.len != 0: return hexToSeqByte(s)

  template testHashToBaseFP2(id, constants: untyped) =
    proc `test _ id`() =
      # We create a proc to avoid allocating too much globals.
      constants

      let pmsg = if msg.len == 0: nil
                 else: cast[ptr byte](msg[0].unsafeAddr)
      let pdst = cast[ptr byte](dst[0].unsafeAddr)

      var ctx: HMAC[sha256]
      # Important: do we need to include the null byte at the end?
      let pointG2 = hashToBaseFP2(
        ctx,
        pmsg, msg.len.uint + 1,
        ctr,
        pdst, dst.len.uint
      )
      echo pointG2

    `test _ id`()

  block: # hashToBaseFP2
    testHashToBaseFP2 1:
      let
        msg = "msg"
        ctr = 0'i8
        dst = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"

      let e = [
        "0x3852c6c62ecd4e04360c24e8ddeac03661b07575a60d6fb7b0a90ce0bb7c7667624fbeea77777e52099dd43356e03192b3d4d27264fd09d0afadda24f48b6f2c",
        "0x099695b4dc8d5dbebc73a9856cc859a3e5317e9a9e0459ee8fc03646bdcfe30125aa434dda228311f25d8c227d5eee289dd6a50897c08397565bc826c5c4113d"
      ]
