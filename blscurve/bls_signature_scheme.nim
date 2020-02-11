# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Implementation of BLS signature scheme (Boneh-Lynn-Shacham)
# following IETF standardization
# Target Ethereum 2.0 specification after v0.10.
#
# Specification:
# - https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-00#section-5.5
# - https://github.com/cfrg/draft-irtf-cfrg-bls-signature
#
# Ethereum 2.0 specification targets minimul-pubkey-size
# so public keys are on curve subgroup G1
# and signatures are on curve subgroup G2
#
# We reuse the IETF types and procedure names
# Cipher suite ID: BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_NUL_

import
  # third-party
  nimcrypto/[hmac, sha2],
  # internal
  ./milagro, ./common, ./hkdf

# Public Types
# ----------------------------------------------------------------------

type
  SecretKey* = object
    ## A secret key in the BLS (Boneh-Lynn-Shacham) signature scheme.
    ## This secret key SHOULD be protected against:
    ## - side-channel attacks:
    ##     implementation must perform exactly the same memory access
    ##     and execute the same step. In other words it should run in constant time.
    ##     Furthermore, retrieval of secret key data has been done by reading
    ##     voltage and power usage on embedded devices
    ## - memory dumps:
    ##     core dumps in case of program crash could leak the data
    ## - root attaching to process:
    ##     a root process like a debugger could attach and read the secret key
    ## - key remaining in memory:
    ##     if the key is not securely erased from memory, it could be accessed
    ##
    ## Long-term storage of this key also requires adequate protection.
    ##
    ## At the moment, the nim-blscurve library does not guarantee such protections
    intVal: BIG_384

  PublicKey* = object
    ## A public key in the BLS (Boneh-Lynn-Shacham) signature scheme.
    point: GroupG1

  Signature* = object
    ## A digital signature of a message using the BLS (Boneh-Lynn-Shacham) signature scheme.
    point: GroupG2

# Public API
# ----------------------------------------------------------------------

func keyGen(ikm: openarray[byte], publicKey: var PublicKey, secretKey: var SecretKey): bool =
  ## TODO: this is WIP
  ##
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

  if ikm.len < 32: return false

  # TODO: change HKDF to openarray API so we can use const string
  let salt = "BLS-SIG-KEYGEN-SALT-"
  var ctx: HMAC[sha256]
  var prk: MDigest[sha256.bits]

  ctx.hkdfExtract(
    prk,
    cast[ptr byte](salt[0].unsafeAddr), salt.len.uint,
    ikm[0].unsafeAddr, ikm.len.uint
  )

  # prime order r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
  # const L = ceil((1.5 * ceil(log2(r))) / 8)

  # var okm: array[L, byte]
  # ctx.hkdfExpand(prk, "", 0, okm[0].addr, L)
  # var dOKM: DBIG_384
  # discard dOKM.fromBytes(OKM)
  var x: BIG_384
  # {.noSideEffect.}:
  #   BIG_384_dmod(x, dOKM, FIELD_Modulus) # is FIELD_Modulus correct or should we use `r`
