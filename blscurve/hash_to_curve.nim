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

  loopIter(e1, 1)
  loopIter(e2, 2)

  result.fromBigs(e1, e2)

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
