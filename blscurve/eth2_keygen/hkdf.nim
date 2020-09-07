# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# TODO: Move into nimcrypto
# Merge with: https://github.com/status-im/nim-eth/blob/b7ebf8ed/eth/p2p/discoveryv5/hkdf.nim

# HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
# https://tools.ietf.org/html/rfc5869
#
# Overview
# ----------------------------------------------------------------------
# HKDF follows the "extract-then-expand" paradigm, where the KDF
# logically consists of two modules.  The first stage takes the input
# keying material and "extracts" from it a fixed-length pseudorandom
# key K.  The second stage "expands" the key K into several additional
# pseudorandom keys (the output of the KDF).
#
#
# 2.2.  Step 1: Extract
# HKDF-Extract(salt, IKM) -> PRK
#
# Options:
#   Hash     a hash function; HashLen denotes the length of the
#             hash function output in octets
#
# Inputs:
#   salt     optional salt value (a non-secret random value);
#             if not provided, it is set to a string of HashLen zeros.
#   IKM      input keying material
#
# Output:
#   PRK      a pseudorandom key (of HashLen octets)
#
# The output PRK is calculated as follows:
#
# PRK = HMAC-Hash(salt, IKM)
#
#
#
# 2.3.  Step 2: Expand
#
# HKDF-Expand(PRK, info, L) -> OKM
#
# Options:
#   Hash     a hash function; HashLen denotes the length of the
#             hash function output in octets
#
# Inputs:
#   PRK      a pseudorandom key of at least HashLen octets
#             (usually, the output from the extract step)
#   info     optional context and application specific information
#             (can be a zero-length string)
#   L        length of output keying material in octets
#             (<= 255*HashLen)
#
# Output:
#   OKM      output keying material (of L octets)
#
# The output OKM is calculated as follows:
#
# N = ceil(L/HashLen)
# T = T(1) | T(2) | T(3) | ... | T(N)
# OKM = first L octets of T
#
# where:
# T(0) = empty string (zero length)
# T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
# T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
# T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
# ...
#
# (where the constant concatenated to the end of each T(n) is a
# single octet.)

{.push raises: [Defect].}

import nimcrypto/hmac

func hkdfExtract*[T;S,I: char|byte](ctx: var HMAC[T],
                     prk: var MDigest[T.bits],
                     salt: openArray[S],
                     ikm: openArray[I],
                     append: static openArray[I]
                    ) =
  ## "Extract" step of HKDF.
  ## Extract a fixed size pseudom-random key
  ## from an optional salt value
  ## and a secret input keying material.
  ##
  ## Inputs:
  ## - salt: a buffer to an optional salt value (set to nil if unused)
  ## - ikm: "input keying material", the secret value to hash.
  ##
  ##   Compared to the spec we add a specific append procedure to do
  ##   IKM || I2OSP(0, 1)
  ##   without having to allocate the secret IKM on the heap
  ##
  ## Output:
  ## - prk: a pseudo random key of fixed size. The size is the same as the cryptographic hash chosen.
  ##
  ## Temporary:
  ## - ctx: a HMAC["cryptographic-hash"] context, for example HMAC[sha256].

  mixin init, update, finish
  ctx.init(salt)
  ctx.update(ikm)
  when append.len > 0:
    ctx.update(append)
  discard ctx.finish(prk.data)

  # ctx.clear() - TODO: very expensive

func hkdfExpand*[T;I,A: char|byte](ctx: var HMAC[T],
                    prk: MDigest[T.bits],
                    info: openArray[I],
                    append: static openArray[A],
                    output: var openArray[byte]
                  ) =
  ## "Expand" step of HKDF
  ## Expand a fixed size pseudo random-key
  ## into several pseudo-random keys
  ##
  ## Inputs:
  ## - prk: a pseudo random key (PRK) of fixed size. The size is the same as the cryptographic hash chosen.
  ## - info: optional context and application specific information (set to nil if unused)
  ## - append:
  ##   Compared to the spec we add a specific append procedure to do
  ##   OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
  ##   without having additional allocation on the heap
  ## Output:
  ## - output: OKM (output keying material). The PRK is expanded to match
  ##           the output length, the result is stored in output.
  ##
  ## Temporary:
  ## - ctx: a HMAC["cryptographic-hash"] context, for example HMAC[sha256].
  mixin init, update, finish

  const HashLen = T.bits div 8

  static: doAssert T.bits >= 0
  # assert output.len <= 255*HashLen

  var N = output.len div HashLen
  if output.len mod HashLen != 0:
    inc N

  var t: MDigest[T.bits]
  let oArray = cast[ptr UncheckedArray[byte]](output)

  for i in 0 ..< N:
    ctx.init(prk.data)
    # T(0) = empty string
    if i != 0:
      ctx.update(t.data)
    ctx.update(info)
    when append.len > 0:
      ctx.update(append)
    ctx.update([uint8(i)+1]) # For byte 255, this append "0" and not "256"
    discard ctx.finish(t.data)

    let iStart = i * HashLen
    let size = min(HashLen, output.len - iStart)
    copyMem(oArray[iStart].addr, t.data.addr, size)

  # ctx.clear() - TODO: very expensive

# Test vectors
# ----------------------------------------------------------------------
# https://tools.ietf.org/html/rfc5869#appendix-A

{.pop.}

when isMainModule:
  import stew/byteutils, nimcrypto/[sha, sha2]

  proc hexToBytes(s: string): seq[byte] =
    if s.len != 0: return hexToSeqByte(s)

  template test(id, constants: untyped) =
    proc `test _ id`() =
      # We create a proc to avoid allocating too much globals.
      constants

      let
        bikm = hexToBytes(IKM)
        bsalt = hexToBytes(salt)
        binfo = hexToBytes(info)
        bprk = hexToBytes(PRK)
        bokm = hexToBytes(OKM)

      var output = newSeq[byte](L)
      var ctx: HMAC[HashType]
      var prk: MDigest[HashType.bits]

      # let salt = if bsalt.len == 0: nil
      #            else: bsalt[0].unsafeAddr
      # let ikm = if bikm.len == 0: nil
      #           else: bikm[0].unsafeAddr
      # let info = if binfo.len == 0: nil
      #            else: binfo[0].unsafeAddr
      let
        salt = bsalt
        ikm = bikm
        info = binfo

      hkdfExtract(ctx, prk, salt, ikm)
      hkdfExpand(ctx, prk, info, output)

      doAssert @(prk.data) == bprk, "\nComputed     0x" & toHex(prk.data) &
                                    "\nbut expected " & PRK & '\n'
      doAssert output == bokm, "\nComputed     0x" & toHex(output) &
                               "\nbut expected " & OKM & '\n'
      echo "HKDF Test ", astToStr(id), " - SUCCESS"

    `test _ id`()

  test 1: # Basic test case with SHA-256
    type HashType = sha256
    const
      IKM  = "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
      salt = "0x000102030405060708090a0b0c"
      info = "0xf0f1f2f3f4f5f6f7f8f9"
      L    = 42

      PRK  = "0x077709362c2e32df0ddc3f0dc47bba63" &
             "90b6c73bb50f9c3122ec844ad7c2b3e5"
      OKM  = "0x3cb25f25faacd57a90434f64d0362f2a" &
             "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" &
             "34007208d5b887185865"

  test 2: # Test with SHA-256 and longer inputs/outputs
    type HashType = sha256
    const
      IKM  =  "0x000102030405060708090a0b0c0d0e0f" &
              "101112131415161718191a1b1c1d1e1f" &
              "202122232425262728292a2b2c2d2e2f" &
              "303132333435363738393a3b3c3d3e3f" &
              "404142434445464748494a4b4c4d4e4f"
      salt =  "0x606162636465666768696a6b6c6d6e6f" &
              "707172737475767778797a7b7c7d7e7f" &
              "808182838485868788898a8b8c8d8e8f" &
              "909192939495969798999a9b9c9d9e9f" &
              "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
      info =  "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" &
              "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" &
              "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" &
              "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" &
              "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
      L    = 82

      PRK  =  "0x06a6b88c5853361a06104c9ceb35b45c" &
              "ef760014904671014a193f40c15fc244"
      OKM  =  "0xb11e398dc80327a1c8e7f78c596a4934" &
              "4f012eda2d4efad8a050cc4c19afa97c" &
              "59045a99cac7827271cb41c65e590e09" &
              "da3275600c2f09b8367793a9aca3db71" &
              "cc30c58179ec3e87c14c01d5c1f3434f" &
              "1d87"

  test 3: # Test with SHA-256 and zero-length salt/info
    type HashType = sha256
    const
      IKM  = "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
      salt = ""
      info = ""
      L    = 42

      PRK  = "0x19ef24a32c717b167f33a91d6f648bdf" &
             "96596776afdb6377ac434c1c293ccb04"
      OKM  = "0x8da4e775a563c18f715f802a063c5a31" &
             "b8a11f5c5ee1879ec3454e5f3c738d2d" &
             "9d201395faa4b61a96c8"

  test 4: # Basic test case with SHA-1
    type HashType = sha1
    const
      IKM  = "0x0b0b0b0b0b0b0b0b0b0b0b"
      salt = "0x000102030405060708090a0b0c"
      info = "0xf0f1f2f3f4f5f6f7f8f9"
      L    = 42

      PRK  = "0x9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"
      OKM  = "0x085a01ea1b10f36933068b56efa5ad81" &
             "a4f14b822f5b091568a9cdd4f155fda2" &
             "c22e422478d305f3f896"

  test 5: # Test with SHA-1 and longer inputs/outputs
    type HashType = sha1
    const
      IKM  = "0x000102030405060708090a0b0c0d0e0f" &
             "101112131415161718191a1b1c1d1e1f" &
             "202122232425262728292a2b2c2d2e2f" &
             "303132333435363738393a3b3c3d3e3f" &
             "404142434445464748494a4b4c4d4e4f"
      salt = "0x606162636465666768696a6b6c6d6e6f" &
             "707172737475767778797a7b7c7d7e7f" &
             "808182838485868788898a8b8c8d8e8f" &
             "909192939495969798999a9b9c9d9e9f" &
             "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
      info = "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" &
             "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" &
             "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" &
             "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" &
             "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
      L    = 82

      PRK  = "0x8adae09a2a307059478d309b26c4115a224cfaf6"
      OKM  = "0x0bd770a74d1160f7c9f12cd5912a06eb" &
             "ff6adcae899d92191fe4305673ba2ffe" &
             "8fa3f1a4e5ad79f3f334b3b202b2173c" &
             "486ea37ce3d397ed034c7f9dfeb15c5e" &
             "927336d0441f4c4300e2cff0d0900b52" &
             "d3b4"

  test 6: # Test with SHA-1 and zero-length salt/info
    type HashType = sha1
    const
      IKM  = "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
      salt = ""
      info = ""
      L    = 42

      PRK  = "0xda8c8a73c7fa77288ec6f5e7c297786aa0d32d01"
      OKM  = "0x0ac1af7002b3d761d1e55298da9d0506" &
             "b9ae52057220a306e07b6b87e8df21d0" &
             "ea00033de03984d34918"

  test 7: # Test with SHA-1, salt not provided (defaults to HashLen zero octets),
          # zero-length info
    type HashType = sha1
    const
      IKM  = "0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
      salt = ""
      info = ""
      L    = 42

      PRK  = "0x2adccada18779e7c2077ad2eb19d3f3e731385dd"
      OKM  = "0x2c91117204d745f3500d636a62f64f0a" &
             "b3bae548aa53d423b0d1f27ebba6f5e5" &
             "673a081d70cce7acfc48"
