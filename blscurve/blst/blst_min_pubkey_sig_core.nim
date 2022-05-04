# Nim-BLST
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02
#
# Variant Minimal-pubkey-size:
#   public keys are points in G1, signatures are
#   points in G2.
#   Implementations using signature aggregation SHOULD use this
#   approach, since the size of (PK_1, ..., PK_n, signature) is
#   dominated by the public keys even for small n.

# We expose the same API as MIRACL
#
# Design:
# - We check public keys and signatures at deserialization
#   - non-zero
#   - in the correct subgroup
#   The primitives called assume that input are already subgroup-checked
#   and so do not call "KeyValidate" again in verification procs.

# Core verification
import
  # Status libraries
  stew/byteutils,
  # Internals
  ./blst_lowlevel

# Batch verification - scalar blinding
import ./sha256_abi

# TODO: Consider keeping the compressed keys/signatures in memory
#       to divide mem usage by 2
#       i.e. use the staging "pk2" variants like
#       - blst_sk_to_pk2_in_g1
#       - blst_sign_pk2_in_g1

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
    ##
    ## Guarantees:
    ## - SecretKeys are always created (via hkdf_mod_r) or deserialized (via `fromBytes`)
    ##   so that SK < BLS12-381 curve order.
    scalar: blst_scalar

  PublicKey* = object
    ## A public key in the BLS (Boneh-Lynn-Shacham) signature scheme.
    point: blst_p1_affine

  # We split Signature and AggregateSignature?
  # This saves 1/3 of size as well as signature
  # can be affine (2 coordinates) while aggregate has to be jacobian/projective (3 coordinates)
  Signature* = object
    ## A digital signature of a message using the BLS (Boneh-Lynn-Shacham) signature scheme.
    point: blst_p2_affine

  AggregateSignature* = object
    ## An aggregated Signature
    point: blst_p2

  AggregatePublicKey* = object
    ## An aggregated Public Key
    point: blst_p1

  ProofOfPossession* = object
    ## A separate public key in the Proof-of-Possession BLS signature variant scheme
    point: blst_p2_affine

func `==`*(a, b: SecretKey): bool {.error: "Comparing secret keys is not allowed".}
  ## Disallow comparing secret keys. It would require constant-time comparison,
  ## and it doesn't make sense anyway.

func `==`*(a, b: PublicKey or Signature or ProofOfPossession): bool {.inline.} =
  ## Check if 2 BLS signature scheme objects are equal
  when a.point is blst_p1_affine:
    bool blst_p1_affine_is_equal(a.point, b.point)
  else:
    bool blst_p2_affine_is_equal(a.point, b.point)

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

# Primitives
# ----------------------------------------------------------------------

func publicFromSecret*(pubkey: var PublicKey, seckey: SecretKey): bool =
  ## Generates a public key from a secret key
  ##
  ## Returns:
  ## - false is secret key is invalid (SK == 0 or >= BLS12-381 curve order),
  ##   true otherwise
  ##   By construction no public API should ever instantiate
  ##   an invalid secretkey in the first place.
  if seckey.vec_is_zero():
    return false
  if not seckey.scalar.blst_sk_check().bool:
    return false
  var pk {.noinit.}: blst_p1
  pk.blst_sk_to_pk_in_g1(seckey.scalar)
  pubkey.point.blst_p1_to_affine(pk)
  return true

func rawFromPublic*(raw: var array[48, byte], pubkey: PublicKey) {.inline.} =
  ## Dump a public key to raw bytes compressed form
  raw.blst_p1_affine_compress(pubkey.point)

# Aggregate
# ----------------------------------------------------------------------

template genAggregatorProcedures(
           Aggregate: typedesc[AggregateSignature or AggregatePublicKey],
           BaseType: typedesc[Signature or PublicKey],
           p1_or_p2: untyped
         ): untyped =
  func init*(agg: var Aggregate, elem: BaseType) {.inline.} =
    ## Initialize an aggregate signature or public key
    agg.point.`blst _ p1_or_p2 _ from_affine`(elem.point)

  func aggregate*(agg: var Aggregate, elem: BaseType) {.inline.} =
    ## Aggregates an element ``elem`` into ``agg``
    # Precondition n >= 1 is respected
    agg.point.`blst _ p1_or_p2 _ add_or_double_affine`(
      agg.point,
      elem.point
    )

  proc aggregate*(agg: var Aggregate, elems: openArray[BaseType]) =
    ## Aggregates an array of elements `elems` into `agg`
    # Precondition n >= 1 is respected even if elems.len == 0
    for e in elems:
      agg.point.`blst _ p1_or_p2 _ add_or_double_affine`(
        agg.point,
        e.point
      )

  proc finish*(dst: var BaseType, src: Aggregate) {.inline.} =
    ## Canonicalize the Aggregate into a BaseType element
    dst.point.`blst _ p1_or_p2 _ to_affine`(src.point)

  proc aggregateAll*(dst: var BaseType, elems: openArray[BaseType]): bool =
    ## Returns the aggregate of ``elems[0..<elems.len]``.
    ## Important:
    ##   `dst` is overwritten
    ##    if `dst` contains a signature or public key, it WILL NOT be aggregated with `elems`
    ## Array ``elems`` must not be empty!
    ##
    ## Returns false if `elems` is the empty array
    ## and true otherwise
    if len(elems) == 0:
      # Spec precondition
      return false
    var agg{.noinit.}: Aggregate
    agg.init(elems[0])
    agg.aggregate(elems.toOpenArray(1, elems.high))
    dst.finish(agg)
    return true

genAggregatorProcedures(AggregateSignature, Signature, p2)
genAggregatorProcedures(AggregatePublicKey, PublicKey, p1)

# Core operations
# ----------------------------------------------------------------------
# Note: unlike the IETF standard, we stay in the curve domain
#       instead of serializing/deserializing public keys and signatures
#       from octet strings/byte arrays to/from G1 or G2 point repeatedly
# Note: functions have the additional DomainSeparationTag defined
#       in https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09
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
  # Spec
  # 1. Q = hash_to_point(message)
  # 2. R = SK * Q
  # 3. signature = point_to_signature(R)
  # 4. return signature
  var sig{.noinit.}: blst_p2
  sig.blst_hash_to_g2(
    message,
    domainSepTag,
    aug = ""
  )
  sig.blst_sign_pk_in_g1(sig, secretKey.scalar)
  signature.point.blst_p2_to_affine(sig)

func coreVerify*[T: byte|char](
       publicKey: PublicKey,
       message: openArray[T],
       sig_or_proof: Signature or ProofOfPossession,
       domainSepTag: static string): bool {.inline.} =
  ## Check that a signature (or proof-of-possession) is valid
  ## for a message (or serialized publickey) under the provided public key
  BLST_SUCCESS == blst_core_verify_pk_in_g1(
    publicKey.point,
    sig_or_proof.point,
    hash_or_encode = kHash,
    message,
    domainSepTag,
    aug = ""
  )

func coreVerifyNoGroupCheck*[T: byte|char](
       publicKey: PublicKey,
       message: openArray[T],
       sig_or_proof: Signature or ProofOfPossession,
       domainSepTag: static string): bool {.noinline.} =
  ## Check that a signature (or proof-of-possession) is valid
  ## for a message (or serialized publickey) under the provided public key
  ## This assumes that the Public Key and Signatures
  ## have been pre group checked (likely on deserialization)
  var ctx{.noinit.}: blst_pairing
  ctx.blst_pairing_init(
    hash_or_encode = kHash,
    domainSepTag
  )
  let ok = BLST_SUCCESS == ctx.blst_pairing_chk_n_aggr_pk_in_g1(
    publicKey.point.unsafeAddr,
    pk_grpchk = false, # Already grouped checked
    sig_or_proof.point.unsafeAddr,
    sig_grpchk = false, # Already grouped checked
    message,
    aug = ""
  )
  if not ok:
    return false

  ctx.blst_pairing_commit()
  bool ctx.blst_pairing_finalverify(nil)

# Core aggregate operations
# Aggregate Batch of (Publickeys, Messages, Signatures)
# -------------------------------------------------------------
doAssert blst_pairing.sizeof().uint == blst_pairing_sizeof(),
  "BLST pairing context changed size. Please update the wrapper"

type
  ContextCoreAggregateVerify*[DomainSepTag: static string] = object
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
    c: blst_pairing

func init*(ctx: var ContextCoreAggregateVerify) {.inline.} =
  ## initialize an aggregate verification context
  ctx.c.blst_pairing_init(
    hash_or_encode = kHash,
    ctx.DomainSepTag
  ) # C1 = 1 (identity element)

func update*[T: char|byte](
       ctx: var ContextCoreAggregateVerify,
       publicKey: PublicKey,
       message: openArray[T]): bool {.inline.} =
  BLST_SUCCESS == ctx.c.blst_pairing_chk_n_aggr_pk_in_g1(
    publicKey.point.unsafeAddr,
    pk_grpchk = false, # Already grouped checked
    signature = nil,
    sig_grpchk = false, # Already grouped checked
    message,
    aug = ""
  )

func commit(ctx: var ContextCoreAggregateVerify) {.inline.} =
  ## Consolidate all init/update operations done so far
  ## This is a very expensive operation
  ## This MUST be done:
  ## - before merging 2 pairing contexts (for example when distributing computation)
  ## - before finalVerify
  ctx.c.blst_pairing_commit()

func finalVerify(ctx: var ContextCoreAggregateVerify): bool {.inline.} =
  ## Verify a whole batch of (PublicKey, message, Signature) triplets.
  bool ctx.c.blst_pairing_finalverify(nil)

func finish*(ctx: var ContextCoreAggregateVerify, signature: Signature or AggregateSignature): bool =
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

  # We add the signature to the pairing context
  # via `blst_pairing_aggregate_pk_in_g1`
  # instead of via `blst_aggregated_in_g2` + `blst_pairing_finalverify`
  # to save one Miller loop
  # as both `blst_pairing_commit` and `blst_pairing_finalverify(non-nil)`
  # use a Miller loop internally and Miller loops are **very** costly.

  when signature is Signature:
    result = BLST_SUCCESS == ctx.c.blst_pairing_chk_n_aggr_pk_in_g1(
      PK = nil,
      pk_grpchk = false, # Already grouped checked
      signature.point.unsafeAddr,
      sig_grpchk = false, # Already grouped checked
      msg = "",
      aug = ""
    )
  elif signature is AggregateSignature:
    block:
      var sig{.noinit.}: blst_p2_affine
      sig.blst_p2_to_affine(signature.point)
      result = BLST_SUCCESS == ctx.c.blst_pairing_chk_n_aggr_pk_in_g1(
        PK = nil,
        pk_grpchk = false, # Already grouped checked
        sig.point.unsafeAddr,
        sig_grpchk = false, # Already grouped checked
        msg = "",
        aug = ""
      )
  else:
    {.error: "Unreachable".}

  if not result: return

  ctx.commit()
  result = bool ctx.finalVerify()

# Parallelized Batch Verifier primitives
# ----------------------------------------------------------------------
#
# Ultimately this can be merged with the internal ContextCoreAggregateVerify
# but:
# - The previous code was audited
# - For now we only support BLST
#   though MIRACL is straightforward, context merge is just a FP12 multiplication
#   since GT is a multiplicative group.
# - we need to hold cryptographycally secure
#   random bytes to protect against forged signatures
#   that would not pass non-aggregated verification
#   via random scalar blinding
#   https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407/14
#
#
# Tradeoffs:
# - Adds:
#   - a blinding multiplication on G2
#   - a blinding mul on G1 or Fp
# - Saves:
#   - Only 1 Miller Loop per thread (50% pairing)
#   - Only 1 Final Exponentiation per batch (50% pairing cost)
#
# Assuming blinding muls cost 60% of a pairing (worst case with 255-bit blinding)
# verifying 3 signatures would have a base cost of 300
# Batched single threaded the cost would be
# 60*3 (blinding 255-bit) + 50 (Miller) + 50 (final exp) = 280
#
# With 64-bit blinding and ~20% overhead
# (not 15% because no endomorphism acceleration with 64-bit)
# 20*3 (blinding 64-bit) + 50 (Miller) + 50 (final exp) = 160
#
# If split on 2 cores, the critical path is
# 20*2 (blinding 64-bit) + 50 (Miller) + 50 (final exp) = 140
#
# If split on 3 cores, the critical path is
# 20*1 (blinding 64-bit) + 50 (Miller) + 50 (final exp) = 120

type
  ContextMultiAggregateVerify*[DomainSepTag: static string] = object
    ## A context for multi signature verification
    ##
    ## This context holds a secure blinding scalar,
    ## it does not use secret data but it is necessary
    ## to have data not in the control of an attacker
    ## to prevent forging valid aggregated signatures
    ## from 2 invalid individual signatures using
    ## the bilinearity property of pairings.
    ## https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407/14
    c: blst_pairing
    secureBlinding: array[32, byte]

## No Nim checks in OpenMP multithreading land, failure allocates an exception.
## No stacktraces either.
## For debugging a parallel OpenMP region, put "attachGC"
## as the first statement after "omp_parallel"
## Then you can echo strings and reenable stacktraces
{.push stacktrace:off, checks: off.}

func init*[T: char|byte](
       ctx: var ContextMultiAggregateVerify,
       secureRandomBytes: array[32, byte],
       threadSepTag: openArray[T]
     ) =
  ## initialize a multi-signature aggregate verification context
  ## This requires cryptographically secure random bytes
  ## to defend against forged signatures that would not
  ## verify individually but would verify while aggregated
  ## https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407/14
  ##
  ## An optional thread separation tag can be added
  ## so that from a single source of randomness
  ## each thread is seeded with a different state when
  ## used in a multithreading context
  ctx.c.blst_pairing_init(
    hash_or_encode = kHash,
    ctx.DomainSepTag
  ) # C1 = 1 (identity element)

  if threadSepTag.len > 0:
    ctx.secureBlinding.bls_sha256_digest(
      secureRandomBytes,
      threadSepTag
    )
  else:
    ctx.secureBlinding.bls_sha256_digest(
      secureRandomBytes
    )

func update*[T: char|byte](
         ctx: var ContextMultiAggregateVerify,
         publicKey: PublicKey,
         message: openArray[T],
         signature: Signature
       ): bool =
  ## Add a (public key, message, signature) triplet
  ## to a ContextMultiAggregateVerify context
  ##
  ## Assumes that the public key and signature
  ## have been group checked and that the public key is not infinity

  # The derivation of a secure scalar
  # MUST not output 0.
  # HKDF mod R for EIP2333 is suitable.
  # We can also consider using something
  # hardware-accelerated like AES.
  #
  # However the curve order r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
  # is 255 bits and 255-bit scalar mul on G2
  # costs 43% of a pairing and on G1 20%,
  # and we need to multiply both the signature
  # and the public key or message.
  # This blinding scheme would have a lot overhead
  # for single threaded.
  #
  # As we don't protect secret data here
  # and only want extra data not in possession of the attacker
  # we only use a 1..<2^64 random blinding factor.
  # We assume that the attacker cannot resubmit 2^64 times
  # forged public keys and signatures.
  # Discussion https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407

  # We only use the first 8 bytes for blinding
  # but use the full 32 bytes to derive new random scalar
  const blindingBits = 64
  var blindingScalar {.noinit.}: blst_scalar
  block: # Warning: Rolling my own crypto
    let blindingAsU64 = cast[ptr uint64](ctx.secureBlinding.addr)
    let blindingAsArray = cast[ptr array[32, byte]](ctx.secureBlinding.addr)

    ctx.secureBlinding.bls_sha256_digest(ctx.secureBlinding)
    while blindingAsU64[] == 0:
      # Ensure that the least significant bytes are non-zero
      ctx.secureBlinding.bls_sha256_digest(ctx.secureBlinding)
    blindingScalar.blst_scalar_from_lendian(blindingAsArray[])

  BLST_SUCCESS == ctx.c.blst_pairing_chk_n_mul_n_aggr_pk_in_g1(
    publicKey.point.unsafeAddr,
    pk_grpchk = false, # Already grouped checked
    signature.point.unsafeAddr,
    sig_grpchk = false, # Already grouped checked
    scalar = blindingScalar,
    nbits = blindingBits, # Use only the first 64 bits for blinding
    message,
    aug = ""
  )

func commit*(ctx: var ContextMultiAggregateVerify) {.inline.} =
  ## Consolidate all init/update operations done so far
  ## This is a very expensive operation
  ## This MUST be done:
  ## - before merging 2 pairing contexts (for example when distributing computation)
  ## - before finalVerify
  ctx.c.blst_pairing_commit()

func merge*(
       ctx_into: var ContextMultiAggregateVerify,
       ctx_from: sink ContextMultiAggregateVerify): bool {.inline.} =
  ## Merge 2 ContextMultiAggregateVerify contexts
  ## This MUST be preceded by "commit" on each ContextMultiAggregateVerify
  ## There shouldn't be a use-case where ``ctx_from`` is reused afterwards
  ## hence it is marked as sink.
  return BLST_SUCCESS == ctx_into.c.blst_pairing_merge(ctx_from.c)

{.pop.} # stacktraces and checks off

func finalVerify*(ctx: var ContextMultiAggregateVerify): bool {.inline.} =
  ## Verify a whole batch of (PublicKey, message, Signature) triplets.
  result = bool ctx.c.blst_pairing_finalverify(nil)

func getScalar*(sk: SecretKey): blst_scalar =
  return sk.scalar

func fromFr*(t: typedesc[SecretKey], pt: blst_fr): SecretKey =
  var transformed: blst_scalar
  transformed.blst_scalar_from_fr(pt)
  SecretKey(scalar: transformed)

func getPoint*(sig: Signature): blst_p2_affine =
  return sig.point

func fromP2*(s: typedesc[Signature], pt: blst_p2): Signature =
  var transformed: blst_p2_affine
  transformed.blst_p2_to_affine(pt)
  Signature(point: transformed)
