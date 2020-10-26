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
  # Standard library
  std/[os, strutils],
  # third-party
  nimcrypto/[hmac, sha2], stew/endians2,
  # internal
  ../bls_backend,
  ../blst/[blst_lowlevel, sha256_abi],
  ./hkdf

# Note: we can't use HKDF from BLST as it's tagged "static" and so unexported

# Internal BLST procedures
# ----------------------------------------------------------------------
static: doAssert limb_t is uint64
type vec256 = array[4, limb_t]
type vec512 = array[8, limb_t]

# consts.h - don't import header directly due to limb_t redefinition
var BLS12_381_r {.importc.}: vec256
var BLS12_381_rRR {.importc.}: vec256
const r0 = 0xfffffffeffffffff'u64

func limbs_from_be_bytes(
       limbs: var openArray[limb_t],
       bytes: openArray[byte]
     ) {.inline.} =
  # Implementation from BLST vect.h
  # Cannot be used as limbs_t definition conflict with blst.h

  var limb = default(limb_t)
  var n = bytes.len
  var cursor = 0
  while n > 0:
    dec n
    limb = limb shl 8
    limb = limb or bytes[cursor]
    inc cursor
    # According to BLST, the redundant stores
    # are cheaper than a mispredicted branch
    # and compiler can unroll the loop
    limbs[n div sizeof(limb_t)] = limb

# Nim-Beacon-Chain compiles with --march=native by default
{.emit:"""
#if defined(__ADX__) && !defined(__BLST_PORTABLE__) /* e.g. -march=broadwell */
# define mul_mont_sparse_256 mulx_mont_sparse_256
# define redc_mont_256 redcx_mont_256
#endif
""".}

const srcPath = currentSourcePath.rsplit(DirSep, 1)[0]/".."/".."/"vendor"/"blst"/"src"

func redc_mont_256(
      ret: var vec256,
      a: vec512,
      p: vec256,
      n0: limb_t
    ) {.importc, header: srcPath/"vect.h".}
  # Can use the redcx version with adx support

func mul_mont_sparse_256(
      ret: var vec256,
      a, b, p: vec256,
      n0: limb_t
    ) {.importc, header: srcPath/"vect.h".}
  # Can use the mulx version with adx support

# ----------------------------------------------------------------------

func hkdf_mod_r*(secretKey: var SecretKey, ikm: openArray[byte], key_info: string): bool =
  ## Ethereum 2 EIP-2333, extracts this from the BLS signature schemes
  # 1. salt = "BLS-SIG-KEYGEN-SALT-"
  # 2. SK = 0
  # 3. while SK == 0:
  # 4.     salt = H(salt)
  # 5.     PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
  # 6.     OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
  # 7.     SK = OS2IP(OKM) mod r
  # 8. return SK
  const salt0 = "BLS-SIG-KEYGEN-SALT-"
  var ctx: HMAC[sha256]
  var prk: MDigest[sha256.bits]

  secretkey.vec_zero()

  var salt {.noInit.}: array[32, byte]
  salt.bls_sha256_digest(salt0)

  while true:
    # 5. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM || I2OSP(0, 1))
    ctx.hkdfExtract(prk, salt, ikm, [byte 0])
    # curve order r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    # const L = ceil((1.5 * ceil(log2(r))) / 8) = 48
    # https://www.wolframalpha.com/input/?i=ceil%28%281.5+*+ceil%28log2%2852435875175126190479447740508185965837690552500527637822603658699938581184513%29%29%29+%2F+8%29
    # 6. OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
    const L = 48
    var okm: array[L, byte]
    const L_octetstring = L.uint16.toBytesBE()
    ctx.hkdfExpand(prk, key_info, append = L_octetstring, okm)
    # The cast is a workaround for private field access
    let seckey = cast[ptr vec256](secretKey.unsafeAddr)
    #  7. x = OS2IP(OKM) mod r
    var dseckey: vec512
    limbs_from_be_bytes(dseckey, okm)
    {.noSideEffect.}: # Accessing C global constants wrapped in var
      redc_mont_256(seckey[], dseckey, BLS12_381_r, r0)
      mul_mont_sparse_256(seckey[], seckey[], BLS12_381_rRR, BLS12_381_r, r0)

    if bool secretkey.vec_is_zero():
      salt.bls_sha256_digest(salt)
    else:
      return true



func keyGen*(ikm: openarray[byte], publicKey: var PublicKey, secretKey: var SecretKey): bool =
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
  #  Definitions:
  #  - HKDF-Extract is as defined in RFC5869, instantiated with hash H.
  #  - HKDF-Expand is as defined in RFC5869, instantiated with hash H.
  #  - L is the integer given by ceil((1.5 * ceil(log2(r))) / 8).
  #  - "BLS-SIG-KEYGEN-SALT-" is an ASCII string comprising 20 octets.
  #  - "" is the empty string.
  #
  #  Procedure:
  #  1. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM)
  #  2. OKM = HKDF-Expand(PRK, "", L)
  #  3. x = OS2IP(OKM) mod r
  #  4. xP = x * P
  #  5. SK = x
  #  6. PK = point_to_pubkey(xP)
  #  7. return (PK, SK)

  # The cast is a workaround for private field access
  cast[ptr blst_scalar](secretKey.addr)[].blst_keygen(ikm, info = "")
  result = publicKey.publicFromSecret(secretKey)
