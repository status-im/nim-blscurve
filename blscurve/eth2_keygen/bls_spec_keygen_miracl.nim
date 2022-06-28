# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Implementation of Ethereum 2 Key derivation
# https://eips.ethereum.org/EIPS/eip-2333

import
  # third-party
  nimcrypto/[hmac, sha2], stew/endians2,
  # internal
  ../bls_backend,
  ../miracl/[common, milagro],
  ./hkdf

func isZero(seckey: SecretKey): bool {.inline.} =
  ## Returns true if the secret key is zero
  ## Those are invalid
  # The cast is a workaround for private field access
  cast[ptr BIG_384](seckey.unsafeAddr)[].iszilch()

func hkdf_mod_r*(secretKey: var SecretKey, ikm: openArray[byte], key_info: string): bool =
  ## Ethereum 2 EIP-2333, extracts this from the BLS signature schemes
  # 1. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM)
  # 2. OKM = HKDF-Expand(PRK, "", L)
  # 3. SK = OS2IP(OKM) mod r
  # 4. return SK
  # 1. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM || I2OSP(0, 1))
  # 2. OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
  # 3. SK = OS2IP(OKM) mod r
  # 4. return SK
  const salt0 = "BLS-SIG-KEYGEN-SALT-"
  var ctx: HMAC[sha256]
  var prk: MDigest[sha256.bits]

  # The cast is a workaround for private field access
  cast[ptr BIG_384](secretKey.addr)[].zero()

  var salt = sha256.digest(salt0)

  while true:
    # 5. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM || I2OSP(0, 1))
    ctx.hkdfExtract(prk, salt.data, ikm, [byte 0])
    # curve order r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    # const L = ceil((1.5 * ceil(log2(r))) / 8) = 48
    # https://www.wolframalpha.com/input/?i=ceil%28%281.5+*+ceil%28log2%2852435875175126190479447740508185965837690552500527637822603658699938581184513%29%29%29+%2F+8%29
    # 6. OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
    const L = 48
    var okm: array[L, byte]
    const L_octetstring = L.uint16.toBytesBE()
    ctx.hkdfExpand(prk, key_info, append = L_octetstring, okm)
    #  7. x = OS2IP(OKM) mod r
    var dseckey: DBIG_384
    if not dseckey.fromBytes(okm):
      return false
    {.noSideEffect.}:
      # The cast is a workaround for private field access
      BIG_384_dmod(cast[ptr BIG_384](secretKey.addr)[], dseckey, CURVE_Order)

    if secretKey.isZero():
      salt = sha256.digest(salt0)
    else:
      return true

func keyGen*(ikm: openArray[byte], publicKey: var PublicKey, secretKey: var SecretKey, key_info = ""): bool =
  ## Generate a (public key, secret key) pair
  ## from the input keying material `ikm`
  ##
  ## For security, `ikm` MUST be infeasible to guess, for example,
  ## generated from a trusted source of randomness.
  ##
  ## `ikm` MUST be at least 32 bytes long but may be longer
  ##
  ## Key generation is deterministic
  ##
  ## Either the keypair (publickey, secretkey) can be stored or
  ## the `ikm` can be stored and keys can be regenerated on demand.
  ##
  ## Inputs:
  ##   - IKM: a secret array or sequence of bytes
  ##
  ## Outputs:
  ##   - publicKey
  ##   - secretKey
  ##
  ## Returns `true` if generation successful
  ## Returns `false` if generation failed
  ## Generation fails if `ikm` length is less than 32 bytes
  ##
  ## `IKM` and  `secretkey` must be protected against side-channel attacks
  ## including timing attaks, memory dumps, attaching processes, ...
  ## and securely erased from memory.
  ##
  ## At the moment, the nim-blscurve library does not guarantee such protections

  #  (PK, SK) = KeyGen(IKM)
  #
  #  Inputs:
  #  - IKM, a secret octet string. See requirements above.
  #
  #  Outputs:
  #  - PK, a public key encoded as an octet string.
  #  - SK, the corresponding secret key, an integer 0 <= SK < r.
  #
  # Parameters:
  # - key_info, an optional octet string.
  #   If key_info is not supplied, it defaults to the empty string.
  #
  #  Definitions:
  #  - HKDF-Extract is as defined in RFC5869, instantiated with hash H.
  #  - HKDF-Expand is as defined in RFC5869, instantiated with hash H.
  #  - L is the integer given by ceil((3 * ceil(log2(r))) / 16).
  #  - "BLS-SIG-KEYGEN-SALT-" is an ASCII string comprising 20 octets.
  #  - "" is the empty string.
  #
  #  Procedure:
  #  1. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM || I2OSP(0, 1))
  #  2. OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
  #  3. x = OS2IP(OKM) mod r
  #  4. SK = OS2IP(OKM) mod r
  if ikm.len < 32:
    return false

  var ok = secretKey.hkdf_mod_r(ikm, key_info)
  if not ok:
    return false

  #  4. xP = x * P
  #  6. PK = point_to_pubkey(xP)
  ok = publicKey.publicFromSecret(secretKey)
  if not ok:
    return false
  return true
