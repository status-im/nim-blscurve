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
  ./milagro, ./common, ./hkdf, ./hash_to_curve

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

# Primitives
# ----------------------------------------------------------------------
func subgroupCheck(P: GroupG1 or GroupG2): bool =
  ## Checks that a point `P`
  ## is actually in the subgroup G1/G2 of the BLS Curve
  var rP = P
  rP.mul(CURVE_Order)
  result = rP.isInf()

# Aggregate
# ----------------------------------------------------------------------

proc aggregate*(sig1: var Signature, sig2: Signature) =
  ## Aggregates signature ``sig2`` into ``sig1``.
  sig1.point.add(sig2.point)

proc aggregate*(sig: var Signature, sigs: openarray[Signature]) =
  ## Aggregates an array of signatures `sigs` into a signature `sig`
  for s in sigs:
    sig.point.add(s.point)

proc aggregate*(sigs: openarray[Signature]): Signature =
  ## Aggregates array of signatures ``sigs``
  ## and return aggregated signature.
  ##
  ## Array ``sigs`` must not be empty!
  doAssert(len(sigs) > 0)
  result = sigs[0]
  result.add sigs.toOpenArray(1, sigs.high)

# Core operations
# ----------------------------------------------------------------------
# Note: unlike the IETF standard, we stay in the curve domain
#       instead of serializing/deserializing public keys and signatures
#       from octet strings/byte arrays to/from G1 or G2 point repeatedly
# Note: functions have the additional DomainSeparationTag defined
#       in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05

func coreSign[T: byte|char](
       secretKey: SecretKey,
       message: openarray[T],
       domainSepTag: string): Signature =
  ## Computes a signature from a secret key and a message
  # Spec
  # 1. Q = hash_to_point(message)
  # 2. R = SK * Q
  # 3. signature = point_to_signature(R)
  # 4. return signature
  let Q = hashToG2(message, domainSepTag)
  result.point = secretKey.point.mul(Q)

func coreVerify[T: byte|char](
       publicKey: PublicKey,
       message: openarray[T],
       signature: Signature,
       domainSepTag: string): bool =
  ## Check that a signature is valid for a message
  ## under the provided public key
  # Spec
  # 1. R = signature_to_point(signature)
  # 2. If R is INVALID, return INVALID
  # 3. If signature_subgroup_check(R) is INVALID, return INVALID
  # 4. xP = pubkey_to_point(PK)
  # 5. Q = hash_to_point(message)
  # 6. C1 = pairing(Q, xP)
  # 7. C2 = pairing(R, P)
  # 8. If C1 == C2, return VALID, else return INVALID
  #
  # Note for G2 (minimal-pubkey-size)
  # pairing(U, V) := e(V, U)
  # with e the optimal Ate pairing
  #
  # P is the generator for G1 or G2
  # in this case G1 since e(G1, G2) -> GT
  # and pairing(R, P) := e(P, R)

  if not subgroupCheck(signature):
    return false
  let Q = hashToG2(message, domainSepTag)

  # pairing(Q, xP) == pairing(R, P)
  return multiPairing(
           Q, publicKey,
           signature, generator1()
         )

func coreAggregateVerify[T: byte|char](
        publicKeys: openarray[PublicKey],
        messages: openarray[openarray[T]],
        signature: Signature,
        domainSepTag: string): bool =
  ## Check an aggregated signature over several (publickey, message) pairs
  # Spec
  # 1. R = signature_to_point(signature)
  # 2. If R is INVALID, return INVALID
  # 3. If signature_subgroup_check(R) is INVALID, return INVALID
  # 4. C1 = 1 (the identity element in GT)
  # 5. for i in 1, ..., n:
  # 6.     xP = pubkey_to_point(PK_i)
  # 7.     Q = hash_to_point(message_i)
  # 8.     C1 = C1 * pairing(Q, xP)
  # 9. C2 = pairing(R, P)
  # 10. If C1 == C2, return VALID, else return INVALID

  if publicKeys.len != messages.len:
    return false

  if not subgroupCheck(signature):
    return false

  # Implementation strategy
  # -----------------------
  # We are checking that
  # e(pubkey1, msg1) e(pubkey2, msg2) ... e(pubkeyN, msgN) == e(P1, sig)
  # with P1 the generator point for G1
  # For x' = (q^12 - 1)/r
  # - q the BLS12-381 field modulus: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
  # - r the BLS12-381 subgroup size: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
  #
  # constructed from x = -0xd201000000010000
  # - q = (x - 1)² ((x⁴ - x² + 1) / 3) + x
  # - r = (x⁴ - x² + 1)
  #
  # we have the following equivalence by removing the final exponentiation
  # in the optimal ate pairing, and denoting e'(_, _) the pairing without final exponentiation
  # (e'(pubkey1, msg1) e'(pubkey2, msg2) ... e'(pubkeyN, msgN))^x == e'(P1, sig)^x
  #
  # We multiply by the inverse in group GT (e(G1, G2) -> GT)
  # to get the equivalent check that is more efficient to implement
  # (e'(pubkey1, msg1) e'(pubkey2, msg2) ... e'(pubkeyN, msgN) e'(-P1, sig))^x == 1
  # The generator P1 is on G1 which is cheaper to negate than the signature
  template `&`(point: untyped): untyped = unsafeAddr(point) # ALias

  var C1: array[AteBitsCount, FP12_BLS381]
  PAIR_BLS381_initmp(addr C1[0])                              # C1 = 1 (identity element)
  for i in 0 ..< n:
    let Q = hashToG2(messages[i])                             # Q = hash_to_point(message_i)
    PAIR_BLS381_another(addr C1[0], &Q, &publicKeys[i].point) # C1 = C1 * pairing(Q, xP)
  # Accumulate the multiplicative inverse of C2 into C1
  let nP1 = neg(generator1())
  PAIR_BLS381_another(addr C1[0], &signature.point, &nP1)
  # Optimal Ate Pairing
  var v: FP12_BLS381
  PAIR_BLS381_miller(addr v, addr C1[0])
  PAIR_BLS381_fexp(addr v)

  if FP12_BLS381_isunity(addr v) == 1:
    return true
  return false

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
