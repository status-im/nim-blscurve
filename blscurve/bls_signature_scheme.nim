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

{.push raises: [Defect].}

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

  ProofOfPossession* = object
    ## A separate public key in the Proof-of-Possession BLS signature variant scheme
    point: GroupG2

func `==`*(a, b: SecretKey): bool {.error: "Comparing secret keys is not allowed".}
  ## Disallow comparing secret keys. It would require constant-time comparison,
  ## and it doesn't make sense anyway.

func `==`*(a, b: PublicKey or Signature or ProofOfPossession): bool {.inline.} =
  ## Check if 2 BLS signature scheme objects are equal
  return a.point == b.point

# IO
# ----------------------------------------------------------------------
# Serialization / Deserialization
# As I/O routines are not part of the specifications, they are implemented
# in a separate file. The file is included instead of imported to
# access private fields

include ./bls_sig_io

# Primitives
# ----------------------------------------------------------------------
func subgroupCheck(P: GroupG1 or GroupG2): bool =
  ## Checks that a point `P`
  ## is actually in the subgroup G1/G2 of the BLS Curve
  var rP = P
  {.noSideEffect.}:
    rP.mul(CURVE_Order)
  result = rP.isInf()

func privToPub*(secretKey: SecretKey): PublicKey =
  ## Generates a public key from a secret key
  result.point = generator1()
  result.point.mul(secretKey.intVal)

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
  # TODO: what is the correct empty signature to return?
  doAssert(len(sigs) > 0)
  result = sigs[0]
  result.aggregate(sigs.toOpenArray(1, sigs.high))

# Core operations
# ----------------------------------------------------------------------
# Note: unlike the IETF standard, we stay in the curve domain
#       instead of serializing/deserializing public keys and signatures
#       from octet strings/byte arrays to/from G1 or G2 point repeatedly
# Note: functions have the additional DomainSeparationTag defined
#       in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05
#
# For coreAggregateVerify, we introduce an internal streaming API that
# can handle both
# - publicKeys: openarray[PublicKey], messages: openarray[openarray[T]]
# - pairs: openarray[tuple[publicKeys: seq[PublicKey], message: seq[byte or string]]]
# efficiently for the high-level API
#
# This also allows efficient interleaving of Proof-Of-Possession checks in the high-level API

func coreSign[T: byte|char](
       secretKey: SecretKey,
       message: openarray[T],
       domainSepTag: static string): GroupG2 =
  ## Computes a signature or proof-of-possession
  ## from a secret key and a message
  # Spec
  # 1. Q = hash_to_point(message)
  # 2. R = SK * Q
  # 3. signature = point_to_signature(R)
  # 4. return signature
  result = hashToG2(message, domainSepTag)
  result.mul(secretKey.intVal)

func coreVerify[T: byte|char](
       publicKey: PublicKey,
       message: openarray[T],
       sig_or_proof: Signature or ProofOfPossession,
       domainSepTag: static string): bool =
  ## Check that a signature (or proof-of-possession) is valid
  ## for a message (or serialized publickey) under the provided public key
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

  # Precondition:
  # The public key PK must satisfy KeyValidate(PK) == VALID
  if not subgroupCheck(publicKey.point):
      return false
  if not subgroupCheck(sig_or_proof.point):
    return false
  let Q = hashToG2(message, domainSepTag)

  # pairing(Q, xP) == pairing(R, P)
  return multiPairing(
           Q, publicKey.point,
           sig_or_proof.point, generator1()
         )

type
  ContextCoreAggregateVerify = object
    # Streaming API for Aggregate verification to handle both SoA and AoS data layout
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
    C1: array[AteBitsCount, FP12_BLS381]

func init(ctx: var ContextCoreAggregateVerify) =
  ## initialize an aggregate verification context
  PAIR_BLS381_initmp(addr ctx.C1[0])                                # C1 = 1 (identity element)

template `&`(point: GroupG1 or GroupG2): untyped = unsafeAddr point

func update[T: char|byte](
       ctx: var ContextCoreAggregateVerify,
       publicKey: PublicKey,
       message: openarray[T],
       domainSepTag: static string) =
  let Q = hashToG2(message, domainSepTag)                   # Q = hash_to_point(message_i)
  PAIR_BLS381_another(addr ctx.C1[0], &Q, &publicKey.point) # C1 = C1 * pairing(Q, xP)

func finish(ctx: var ContextCoreAggregateVerify, signature: Signature): bool =
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

  # Accumulate the multiplicative inverse of C2 into C1
  let nP1 = neg(generator1())
  PAIR_BLS381_another(addr ctx.C1[0], &signature.point, &nP1)
  # Optimal Ate Pairing
  var v: FP12_BLS381
  PAIR_BLS381_miller(addr v, addr ctx.C1[0])
  PAIR_BLS381_fexp(addr v)

  if FP12_BLS381_isunity(addr v) == 1:
    return true
  return false

# Public API
# ----------------------------------------------------------------------
#
# There are 3 BLS schemes that differ in handling rogue key attacks
# - basic: requires message signed by an aggregate signature to be distinct
# - message augmentation: signatures are generated over the concatenation of public key and the message
#                         enforcing message signed by different public key to be distinct
# - proof of possession: a separate public key called proof-of-possession is used to allow signing
#                        on the same message while defending against rogue key attacks
# with respective ID / domain separation tag:
# - BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_NUL_
# - BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_AUG_
# - BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_POP_
#   - POP tag: BLS_POP_BLS12381G2-SHA256-SSWU-RO-_POP_
#
# We implement the proof-of-possession scheme
# Compared to the spec API are modified
# to enforce usage of the proof-of-posession (as recommended)

const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
const DST_POP = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

func popProve*(secretKey: SecretKey, publicKey: PublicKey): ProofOfPossession =
  ## Generate a proof of possession for the public/secret keypair
  # 1. xP = SK * P
  # 2. PK = point_to_pubkey(xP)
  # 3. Q = hash_pubkey_to_point(PK)
  # 4. R = SK * Q
  # 5. proof = point_to_signature(R)
  # 6. return proof
  let pk = publicKey.point.getBytes()            # 2. Convert to raw bytes compressed form
  result.point = secretKey.coreSign(pk, DST_POP) # 3-4. hash_to_curve and multiply by secret key

func popProve*(secretKey: SecretKey): ProofOfPossession =
  ## Generate a proof of possession for the public key associated with the input secret key
  ## Note: this internally recomputes the public key, an overload that doesn't is available.
  # 1. xP = SK * P
  # 2. PK = point_to_pubkey(xP)
  # 3. Q = hash_pubkey_to_point(PK)
  # 4. R = SK * Q
  # 5. proof = point_to_signature(R)
  # 6. return proof
  let pubkey = privToPub(secretKey)
  result = popProve(secretKey, pubkey)

func popVerify*(publicKey: PublicKey, proof: ProofOfPossession): bool =
  ## Verify if the proof-of-possession is valid for the public key
  ## returns true if valid or false if invalid
  # 1. R = signature_to_point(proof)
  # 2. If R is INVALID, return INVALID
  # 3. If signature_subgroup_check(R) is INVALID, return INVALID
  # 4. If KeyValidate(PK) is INVALID, return INVALID
  # 5. xP = pubkey_to_point(PK)
  # 6. Q = hash_pubkey_to_point(PK)
  # 7. C1 = pairing(Q, xP)
  # 8. C2 = pairing(R, P)
  # 9. If C1 == C2, return VALID, else return INVALID
  result = coreVerify(publicKey, publicKey.point.getBytes(), proof, DST_POP)

func sign*[T: byte|char](secretKey: SecretKey, message: openarray[T]): Signature =
  ## Computes a signature
  ## from a secret key and a message
  result.point = secretKey.coreSign(message, DST)

func verify*[T: byte|char](
       publicKey: PublicKey,
       proof: ProofOfPossession,
       message: openarray[T],
       signature: Signature) : bool =
  ## Check that a signature is valid for a message
  ## under the provided public key.
  ## returns `true` if the signature is valid, `false` otherwise.
  ##
  ## Compared to the IETF spec API, it is modified to
  ## enforce proper usage of the proof-of-possession
  if not publicKey.popVerify(proof):
    return false
  return publicKey.coreVerify(message, signature, DST)

func verify*[T: byte|char](
       publicKey: PublicKey,
       message: openarray[T],
       signature: Signature) : bool =
  ## Check that a signature is valid for a message
  ## under the provided public key.
  ## returns `true` if the signature is valid, `false` otherwise.
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  return publicKey.coreVerify(message, signature, DST)

func aggregateVerify*(
        publicKeys: openarray[PublicKey],
        proofs: openarray[ProofOfPossession],
        messages: openarray[string or seq[byte]],
        signature: Signature): bool =
  ## Check that an aggregated signature over several (publickey, message) pairs
  ## returns `true` if the signature is valid, `false` otherwise.
  ##
  ## Compared to the IETF spec API, it is modified to
  ## enforce proper usage of the proof-of-possessions
  # Note: we can't have openarray of openarrays until openarrays are first-class value types
  if publicKeys.len != proofs.len or publicKeys != messages.len:
    return false

  var ctx: ContextCoreAggregateVerify
  ctx.init()
  for i in 0 ..< publicKeys.len:
    if not publicKeys[i].popVerify(proofs[i]):
      return false
    ctx.update(publicKeys[i], messages[i], DST)
  return ctx.finish(signature)

func aggregateVerify*(
        publicKeys: openarray[PublicKey],
        messages: openarray[string or seq[byte]],
        signature: Signature): bool =
  ## Check that an aggregated signature over several (publickey, message) pairs
  ## returns `true` if the signature is valid, `false` otherwise.
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  # Note: we can't have openarray of openarrays until openarrays are first-class value types
  if publicKeys.len != messages.len:
    return false

  var ctx: ContextCoreAggregateVerify
  ctx.init()
  for i in 0 ..< publicKeys.len:
    ctx.update(publicKeys[i], messages[i], DST)
  return ctx.finish(signature)

func aggregateVerify*[T: string or seq[byte]](
        publicKey_msg_pairs: openarray[tuple[publicKey: PublicKey, message: T]],
        signature: Signature): bool =
  ## Check that an aggregated signature over several (publickey, message) pairs
  ## returns `true` if the signature is valid, `false` otherwise.
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  # Note: we can't have tuple of openarrays until openarrays are first-class value types
  var ctx: ContextCoreAggregateVerify
  ctx.init()
  for i in 0 ..< publicKey_msg_pairs.len:
    ctx.update(publicKey_msg_pairs[i].publicKey, publicKey_msg_pairs[i].message, DST)
  return ctx.finish(signature)

func fastAggregateVerify*[T: byte|char](
        publicKeys: openarray[PublicKey],
        proofs: openarray[ProofOfPossession],
        message: openarray[T],
        signature: Signature
      ): bool =
  ## Verify the aggregate of multiple signatures on the same message
  ## This function is faster than AggregateVerify
  ## Compared to the IETF spec API, it is modified to
  ## enforce proper usage of the proof-of-posession
  # 1. aggregate = pubkey_to_point(PK_1)
  # 2. for i in 2, ..., n:
  # 3.     next = pubkey_to_point(PK_i)
  # 4.     aggregate = aggregate + next
  # 5. PK = point_to_pubkey(aggregate)
  # 6. return CoreVerify(PK, message, signature)
  if publicKeys.len == 0:
    return false
  if not publicKeys[0].popVerify(proofs[0]):
    return false
  var aggregate = publicKeys[0]
  for i in 1 ..< publicKeys.len:
    if not publicKeys[i].popVerify(proofs[i]):
      return false
    aggregate.point.add(publicKeys[i].point)
  return coreVerify(aggregate, message, signature, DST)

func fastAggregateVerify*[T: byte|char](
        publicKeys: openarray[PublicKey],
        message: openarray[T],
        signature: Signature
      ): bool =
  ## Verify the aggregate of multiple signatures on the same message
  ## This function is faster than AggregateVerify
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  # 1. aggregate = pubkey_to_point(PK_1)
  # 2. for i in 2, ..., n:
  # 3.     next = pubkey_to_point(PK_i)
  # 4.     aggregate = aggregate + next
  # 5. PK = point_to_pubkey(aggregate)
  # 6. return CoreVerify(PK, message, signature)
  if publicKeys.len == 0:
    return false
  var aggregate = publicKeys[0]
  for i in 1 ..< publicKeys.len:
    aggregate.point.add(publicKeys[i].point)
  return coreVerify(aggregate, message, signature, DST)

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

  if ikm.len < 32:
    return false

  const salt = "BLS-SIG-KEYGEN-SALT-"
  var ctx: HMAC[sha256]
  var prk: MDigest[sha256.bits]

  # 1. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM)
  ctx.hkdfExtract(prk, salt, ikm)

  # curve order r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
  # const L = ceil((1.5 * ceil(log2(r))) / 8) = 48
  # https://www.wolframalpha.com/input/?i=ceil%28%281.5+*+ceil%28log2%2852435875175126190479447740508185965837690552500527637822603658699938581184513%29%29%29+%2F+8%29

  #  2. OKM = HKDF-Expand(PRK, "", L)
  const L = 48
  var okm: array[L, byte]
  ctx.hkdfExpand(prk, "", okm)

  #  3. x = OS2IP(OKM) mod r
  #  5. SK = x
  var dseckey: DBIG_384
  if not dseckey.fromBytes(okm):
    return false

  {.noSideEffect.}:
    BIG_384_dmod(secretKey.intVal, dseckey, CURVE_Order)

  #  4. xP = x * P
  #  6. PK = point_to_pubkey(xP)
  publicKey = privToPub(secretKey)
  return true
