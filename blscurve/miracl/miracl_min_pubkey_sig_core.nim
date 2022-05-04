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
    ##
    ## Guarantees:
    ## - SecretKeys are always created (via hkdf_mod_r) or deserialized (via `fromBytes`)
    ##   so that SK < BLS12-381 curve order
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

  AggregatePublicKey*{.borrow:`.`.} = distinct PublicKey
    ## An aggregated Public Key
    ## With MIRACL backend, there is no bit-level
    ## difference from a normal PublicKey

func `==`*(a, b: SecretKey): bool {.error: "Comparing secret keys is not allowed".}
  ## Disallow comparing secret keys. It would require constant-time comparison,
  ## and it doesn't make sense anyway.

func `==`*(a, b: PublicKey or Signature or ProofOfPossession): bool {.inline.} =
  ## Check if 2 BLS signature scheme objects are equal
  return a.point == b.point

# Primitives
# ----------------------------------------------------------------------
func subgroupCheck*(P: GroupG1 or GroupG2): bool =
  ## Checks that a point `P`
  ## is actually in the subgroup G1/G2 of the BLS Curve
  var rP = P
  {.noSideEffect.}:
    rP.mul(CURVE_Order)
  rP.isinf()

func publicFromSecret*(pubkey: var PublicKey, seckey: SecretKey): bool =
  ## Generates a public key from a secret key
  ## Inputs:
  ## - SK, a secret integer such that 1 <= SK < r.
  ##
  ## Outputs:
  ## - PK, a public key encoded as an octet string.
  ##
  ## Returns:
  ## - false is secret key is invalid (SK == 0 or >= BLS12-381 curve order),
  ##   true otherwise
  ##   By construction no public API should ever instantiate
  ##   an invalid secretkey in the first place.
  ##
  ## Side-channel/Constant-time considerations:
  ## The SK content is not revealed unless its value
  ## is exactly 0
  #
  # Procedure:
  # 1. xP = SK * P
  # 2. PK = point_to_pubkey(xP)
  # 3. return PK
  #
  # Always != 0:
  # keyGen, deriveChild_secretKey, fromHex, fromBytes guarantee that.
  if seckey.intVal.iszilch():
    return false
  {.noSideEffect.}:
    if seckey.intVal.cmp(CURVE_Order) != -1:
      return false
  pubkey.point = generator1()
  pubkey.point.mul(seckey.intVal)
  return true

func rawFromPublic*(raw: var array[48, byte], pubkey: PublicKey) {.inline.} =
  ## Dump a public key to raw bytes compressed form
  raw = pubkey.point.getBytes()

# IO
# ----------------------------------------------------------------------
# Serialization / Deserialization
# As I/O routines are not part of the specifications, they are implemented
# in a separate file. The file is included instead of imported to
# access private fields
#
# PublicKeys are infinity checked and subgroup checked on deserialization
# Signatures are subgroup-checked on deserialization

include ./bls_sig_io

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

template genAggregatorProcedures(
           Aggregate: typedesc[AggregateSignature or AggregatePublicKey],
           BaseType: typedesc[Signature or PublicKey]
         ): untyped =

  func init*(agg: var Aggregate, elem: BaseType) {.inline.} =
    ## Initialize an aggregate signature or public key
    agg = Aggregate(elem)

  proc aggregate*(agg: var Aggregate, elem: BaseType) {.inline.} =
    ## Aggregates an element ``elem`` into ``agg``
    # Precondition n >= 1 is respected
    agg.point.add(elem.point)

  proc aggregate*(agg: var Aggregate, elems: openArray[BaseType]) =
    ## Aggregates an array of elements `elems` into `agg`
    # Precondition n >= 1 is respected even if sigs.len == 0
    for e in elems:
      agg.aggregate(e)

  proc finish*(dst: var BaseType, src: Aggregate) {.inline.} =
    ## Canonicalize the Aggregate into a BaseType element
    dst = BaseType(src)

  proc aggregateAll*(dst: var BaseType, elems: openArray[BaseType]): bool =
    ## Returns the aggregate signature of ``elems[0..<elems.len]``.
    ## Important:
    ##   `dst` is overwritten
    ##    if `dst` contains a signature or public key, it WILL NOT be aggregated with `sigs`
    ## Array ``elems`` must not be empty!
    ##
    ## Returns false if `elems` is the empty array
    ## and true otherwise
    if len(elems) == 0:
      return false
    dst = elems[0]
    for i in 1 ..< elems.len:
      dst.point.add(elems[i].point)
    return true

genAggregatorProcedures(AggregateSignature, Signature)
genAggregatorProcedures(AggregatePublicKey, PublicKey)

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
# - publicKeys: openArray[PublicKey], messages: openArray[openArray[T]]
# - pairs: openArray[tuple[publicKeys: seq[PublicKey], message: seq[byte or string]]]
# efficiently for the high-level API
#
# This also allows efficient interleaving of Proof-Of-Possession checks in the high-level API

func coreSign*[T: byte|char](
       signature: var (Signature or ProofOfPossession),
       secretKey: SecretKey,
       message: openArray[T],
       domainSepTag: static string) =
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
  signature.point = hashToG2(message, domainSepTag)
  signature.point.mul(secretKey.intVal)

func coreVerify*[T: byte|char](
       publicKey: PublicKey,
       message: openArray[T],
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
  if publicKey.point.isinf():
    return false
  if not subgroupCheck(publicKey.point):
    return false
  let Q = hashToG2(message, domainSepTag)

  # pairing(Q, xP) == pairing(R, P)
  return multiPairing(
           Q, publicKey.point,
           sig_or_proof.point, generator1()
         )

func coreVerifyNoGroupCheck*[T: byte|char](
       publicKey: PublicKey,
       message: openArray[T],
       sig_or_proof: Signature or ProofOfPossession,
       domainSepTag: static string): bool =
  ## Check that a signature (or proof-of-possession) is valid
  ## for a message (or serialized publickey) under the provided public key
  ##
  ## PublicKey MUST be non-zero
  ## `publicFromSecret`, `fromHex`, `fromBytes` ensure that.
  ##
  ## Assumes that infinity pubkey and subgroup checks were done
  ## for example at deserialization
  let Q = hashToG2(message, domainSepTag)

  # pairing(Q, xP) == pairing(R, P)
  return multiPairing(
           Q, publicKey.point,
           sig_or_proof.point, generator1()
         )

type
  ContextCoreAggregateVerify*[DomainSepTag: static string] = object
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

func init*(ctx: var ContextCoreAggregateVerify) {.inline.} =
  ## initialize an aggregate verification context
  PAIR_BLS12381_initmp(addr ctx.C1[0])

template `&`(point: GroupG1 or GroupG2): untyped = unsafeAddr point

func update*[T: char|byte](
       ctx: var ContextCoreAggregateVerify,
       publicKey: PublicKey,
       message: openArray[T]): bool =
  if not subgroupCheck(publicKey.point):
    return false
  let Q = hashToG2(message, ctx.DomainSepTag)                   # Q = hash_to_point(message_i)
  PAIR_BLS12381_another(addr ctx.C1[0], &Q, &publicKey.point) # C1 = C1 * pairing(Q, xP)
  return true

func finish*(ctx: var ContextCoreAggregateVerify, signature: Signature): bool =
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
