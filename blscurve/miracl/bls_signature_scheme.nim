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
# - https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02
# - https://github.com/cfrg/draft-irtf-cfrg-bls-signature
#
# Ethereum 2.0 specification targets minimul-pubkey-size
# so public keys are on curve subgroup G1
# and signatures are on curve subgroup G2
#
# We reuse the IETF types and procedure names
# Cipher suite ID: BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_NUL_
#
# Draft changes: https://tools.ietf.org/rfcdiff?url1=https://tools.ietf.org/id/draft-irtf-cfrg-bls-signature-00.txt&url2=https://tools.ietf.org/id/draft-irtf-cfrg-bls-signature-02.txt

{.push raises: [Defect].}

import
  # third-party
  nimcrypto/[hmac, sha2],
  stew/endians2,
  # internal
  ./milagro, ./common

import ./hash_to_curve

# Public Types
# ----------------------------------------------------------------------

type
  SecretKey* = object
    ## A secret key in the BLS (Boneh-Lynn-Shacham) signature scheme.
    ##
    ## This SecretKey is non-zero by construction.
    ##
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

  AggregateSignature*{.borrow:`.`.} = distinct Signature
    ## An aggregated Signature.
    ## With MIRACL backend, there is no bit-level
    ## difference from a normal signature

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

func isZero*(seckey: SecretKey): bool =
  ## Returns true if the secret key is zero
  ## Those are invalid
  result = seckey.intVal.iszilch()

func publicFromSecret*(pubkey: var PublicKey, seckey: SecretKey): bool {.noInit.} =
  ## Generates a public key from a secret key
  ## Inputs:
  ## - SK, a secret integer such that 1 <= SK < r.
  ##
  ## Outputs:
  ## - PK, a public key encoded as an octet string.
  ##
  ## Returns:
  ## - false is secret key is invalid (SK == 0), true otherwise
  ##
  ## Side-channel/Constant-time considerations:
  ## The SK content is not revealed unless its value
  ## is exactly 0
  #
  # Procedure:
  # 1. xP = SK * P
  # 2. PK = point_to_pubkey(xP)
  # 3. return PK


  # Always != 0:
  # keyGen, deriveChild_secretKey, fromHex, fromBytes guarantee that.
  if seckey.isZero():
    return false
  pubkey.point = generator1()
  pubkey.point.mul(secKey.intVal)
  return true

# Aggregate
# ----------------------------------------------------------------------
# 2.8.  Aggregate (BLSv4)
#
#    The Aggregate algorithm aggregates multiple signatures into one.
#    signature = Aggregate((signature_1, ..., signature_n))
#
#    Inputs:
#    - signature_1, ..., signature_n, octet strings output by
#      either CoreSign or Aggregate.
#
#    Outputs:
#    - signature, an octet string encoding a aggregated signature
#      that combines all inputs; or INVALID.
#
#    Precondition: n >= 1, otherwise return INVALID.
#
#    Procedure:
#    1. aggregate = signature_to_point(signature_1)
#    2. If aggregate is INVALID, return INVALID
#    3. for i in 2, ..., n:
#    4.     next = signature_to_point(signature_i)
#    5.     If next is INVALID, return INVALID
#    6.     aggregate = aggregate + next
#    7. signature = point_to_signature(aggregate)
#
# Comments:
# - This does not require signatures to be non-zero

func init*(agg: var AggregateSignature, sig: Signature) {.inline.} =
  ## Initialize an aggregate signature with a signature
  agg = AggregateSignature(sig)

proc aggregate*(agg: var AggregateSignature, sig: Signature) {.inline.} =
  ## Returns the aggregate signature of ``sig1`` + ``sig2``.
  # Precondition n >= 1 is respected
  agg.point.add(sig.point)

proc aggregate*(agg: var AggregateSignature, sigs: openarray[Signature]) =
  ## Returns the aggregate signature of ``sig1`` + ``sigs[0..<sigs.len]``.
  # Precondition n >= 1 is respected even if sigs.len == 0
  for s in sigs:
    agg.aggregate(s)

proc finish*(sig: var Signature, agg: AggregateSignature) {.inline.} =
  ## Canonicalize the AggregateSignature into a Signature
  sig = Signature(agg)

proc aggregateAll*(dst: var Signature, sigs: openarray[Signature]): bool =
  ## Returns the aggregate signature of ``sigs[0..<sigs.len]``.
  ## Important:
  ##   `dst` is overwritten
  ##    if `dst` contains a signature, it WILL NOT be aggregated with `sigs`
  ## Array ``sigs`` must not be empty!
  ##
  ## Returns false if `sigs` is the empty array
  ## and true otherwise
  if len(sigs) == 0:
    return false
  dst = sigs[0]
  for i in 1 ..< sigs.len:
    dst.point.add(sigs[i].point)
  return true

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
  ##
  ## The SecretKey MUST be directly created via
  ## `keyGen` or `derive_child_secretKey`
  ## or deserialized from `fromBytes` or `fromHex`.
  ## This ensures the precondition that it's not a zero key.
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
  ##
  ## PublicKey MUST be non-zero
  ## `publicFromSecret`, `fromHex`, `fromBytes` ensure that.
  ##
  # Spec
  # 1. R = signature_to_point(signature)
  # 2. If R is INVALID, return INVALID
  # 3. If signature_subgroup_check(R) is INVALID, return INVALID
  # 4. If KeyValidate(PK) is INVALID, return INVALID
  # 5. xP = pubkey_to_point(PK)
  # 6. Q = hash_to_point(message)
  # 7. C1 = pairing(Q, xP)
  # 8. C2 = pairing(R, P)
  # 9. If C1 == C2, return VALID, else return INVALID
  #
  # Note for G2 (minimal-pubkey-size)
  # pairing(U, V) := e(V, U)
  # with e the optimal Ate pairing
  #
  # P is the generator for G1 or G2
  # in this case G1 since e(G1, G2) -> GT
  # and pairing(R, P) := e(P, R)

  # 3. If signature_subgroup_check(R) is INVALID, return INVALID
  if not subgroupCheck(sig_or_proof.point):
    return false
  # 4. If KeyValidate(PK) is INVALID, return INVALID
  # We assumes PK is not 0
  if not subgroupCheck(publicKey.point):
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
    # Precondition: n >= 1, otherwise return INVALID.
    # Procedure:
    # 1.  R = signature_to_point(signature)
    # 2.  If R is INVALID, return INVALID
    # 3.  If signature_subgroup_check(R) is INVALID, return INVALID
    # 4.  C1 = 1 (the identity element in GT)
    # 5.  for i in 1, ..., n:
    # 6.      If KeyValidate(PK_i) is INVALID, return INVALID
    # 7.      xP = pubkey_to_point(PK_i)
    # 8.      Q = hash_to_point(message_i)
    # 9.      C1 = C1 * pairing(Q, xP)
    # 10. C2 = pairing(R, P)
    # 11. If C1 == C2, return VALID, else return INVALID
    C1: array[AteBitsCount, FP12_BLS12381]

func init(ctx: var ContextCoreAggregateVerify) =
  ## initialize an aggregate verification context
  PAIR_BLS12381_initmp(addr ctx.C1[0])                                # C1 = 1 (identity element)

template `&`(point: GroupG1 or GroupG2): untyped = unsafeAddr point

func update[T: char|byte](
       ctx: var ContextCoreAggregateVerify,
       publicKey: PublicKey,
       message: openarray[T],
       domainSepTag: static string): bool =
  if not subgroupCheck(publicKey.point):
    return false
  let Q = hashToG2(message, domainSepTag)                   # Q = hash_to_point(message_i)
  PAIR_BLS12381_another(addr ctx.C1[0], &Q, &publicKey.point) # C1 = C1 * pairing(Q, xP)
  return true

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
  PAIR_BLS12381_another(addr ctx.C1[0], &signature.point, &nP1)
  # Optimal Ate Pairing
  var v: FP12_BLS12381
  PAIR_BLS12381_miller(addr v, addr ctx.C1[0])
  PAIR_BLS12381_fexp(addr v)

  if FP12_BLS12381_isunity(addr v) == 1:
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
  var pubkey {.noInit.}: PublicKey
  let ok {.used.} = pubkey.publicFromSecret(secretKey)
  assert ok, "The secret key is INVALID, it should be initialized non-zero with keyGen or derive_child_secretKey"
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
  ##
  ## The SecretKey MUST be directly created via
  ## `keyGen` or `derive_child_secretKey`
  ## or deserialized from `fromBytes` or `fromHex`.
  ## This ensures the precondition that it's not a zero key.
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
  ##
  ## The PublicKey MUST be directly created via
  ## `publicFromPrivate`
  ## or deserialized from `fromBytes` or `fromHex`.
  ## This ensures the precondition that it's not a zero key.
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
  ##
  ## The PublicKey MUST be directly created via
  ## `publicFromPrivate`
  ## or deserialized from `fromBytes` or `fromHex`.
  ## This ensures the precondition that it's not a zero key.
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
  if not(publicKeys.len >= 1):
    return false

  var ctx: ContextCoreAggregateVerify
  ctx.init()
  for i in 0 ..< publicKeys.len:
    if not publicKeys[i].popVerify(proofs[i]):
      return false
    if not ctx.update(publicKeys[i], messages[i], DST):
      return false
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
  if not(publicKeys.len >= 1):
    return false

  var ctx: ContextCoreAggregateVerify
  ctx.init()
  for i in 0 ..< publicKeys.len:
    if not ctx.update(publicKeys[i], messages[i], DST):
      return false
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
  if not(publicKey_msg_pairs.len >= 1):
    return false
  var ctx: ContextCoreAggregateVerify
  ctx.init()
  for i in 0 ..< publicKey_msg_pairs.len:
    if not ctx.update(publicKey_msg_pairs[i].publicKey, publicKey_msg_pairs[i].message, DST):
      return false
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
