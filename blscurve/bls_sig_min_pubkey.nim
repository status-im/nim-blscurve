# Nim-BLST
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import bls_backend

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

const DST* = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
const DST_POP = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

func popProve*(secretKey: SecretKey, publicKey: PublicKey): ProofOfPossession =
  ## Generate a proof of possession for the public/secret keypair
  # 1. xP = SK * P
  # 2. PK = point_to_pubkey(xP)
  # 3. Q = hash_pubkey_to_point(PK)
  # 4. R = SK * Q
  # 5. proof = point_to_signature(R)
  # 6. return proof
  var pk{.noinit.}: array[48, byte]
  pk.rawFromPublic(publicKey) # 2. Convert to raw bytes compressed form
  result.coreSign(secretKey, pk, DST_POP)     # 3-4. hash_to_curve and multiply by secret key

func popProve*(secretKey: SecretKey): ProofOfPossession =
  ## Generate a proof of possession for the public key associated with the input secret key
  ## Note: this internally recomputes the public key, an overload that doesn't is available.
  # 1. xP = SK * P
  # 2. PK = point_to_pubkey(xP)
  # 3. Q = hash_pubkey_to_point(PK)
  # 4. R = SK * Q
  # 5. proof = point_to_signature(R)
  # 6. return proof
  var pubkey {.noinit.}: PublicKey
  let ok {.used.} = pubkey.publicFromSecret(secretKey)
  assert ok, "The secret key is INVALID, it should be initialized non-zero with keyGen or derive_child_secretKey"
  popProve(secretKey, pubkey)

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
  var pk{.noinit.}: array[48, byte]
  pk.rawFromPublic(publicKey)
  coreVerifyNoGroupCheck(publicKey, pk, proof, DST_POP)

func sign*[T: byte|char](secretKey: SecretKey, message: openArray[T]): Signature =
  ## Computes a signature
  ## from a secret key and a message
  ##
  ## The SecretKey MUST be directly created via
  ## `keyGen` or `derive_child_secretKey`
  ## or deserialized from `fromBytes` or `fromHex`.
  ## This ensures the precondition that it's not a zero key.
  result.coreSign(secretKey, message, DST)

func verify*[T: byte|char](
       publicKey: PublicKey,
       proof: ProofOfPossession,
       message: openArray[T],
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
  ## This ensures the precondition that it's not a zero key
  ## and that is has been subgroup checked
  if not publicKey.popVerify(proof):
    return false
  return publicKey.coreVerifyNoGroupCheck(message, signature, DST)

func verify*[T: byte|char](
       publicKey: PublicKey,
       message: openArray[T],
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
  ## This ensures the precondition that it's not a zero key
  ## and that is has been subgroup checked
  return publicKey.coreVerifyNoGroupCheck(message, signature, DST)

func aggregateVerify*(
        publicKeys: openArray[PublicKey],
        proofs: openArray[ProofOfPossession],
        messages: openArray[string or seq[byte]],
        signature: Signature): bool {.noinline.} =
  ## Check that an aggregated signature over several (publickey, message) pairs
  ## returns `true` if the signature is valid, `false` otherwise.
  ##
  ## Compared to the IETF spec API, it is modified to
  ## enforce proper usage of the proof-of-possessions
  # Note: we can't have openArray of openArrays until openArrays are first-class value types
  if publicKeys.len != proofs.len or publicKeys.len != messages.len:
    return false
  if not(publicKeys.len >= 1):
    # Spec precondition
    return false

  var ctx{.noinit.}: ContextCoreAggregateVerify[DST]

  ctx.init()
  for i in 0 ..< publicKeys.len:
    if not publicKeys[i].popVerify(proofs[i]):
      return false
    if not ctx.update(publicKeys[i], messages[i]):
      return false
  return ctx.finish(signature)

func aggregateVerify*(
        publicKeys: openArray[PublicKey],
        messages: openArray[string or seq[byte]],
        signature: Signature): bool =
  ## Check that an aggregated signature over several (publickey, message) pairs
  ## returns `true` if the signature is valid, `false` otherwise.
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  # Note: we can't have openArray of openArrays until openArrays are first-class value types
  if publicKeys.len != messages.len:
    return false
  if not(publicKeys.len >= 1):
    # Spec precondition
    return false

  var ctx{.noinit.}: ContextCoreAggregateVerify[DST]

  ctx.init()
  for i in 0 ..< publicKeys.len:
    if not ctx.update(publicKeys[i], messages[i]):
      return false
  return ctx.finish(signature)

func aggregateVerify*[T: string or seq[byte]](
        publicKey_msg_pairs: openArray[tuple[publicKey: PublicKey, message: T]],
        signature: Signature): bool =
  ## Check that an aggregated signature over several (publickey, message) pairs
  ## returns `true` if the signature is valid, `false` otherwise.
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  # Note: we can't have tuple of openArrays until openArrays are first-class value types
  if not(publicKey_msg_pairs.len >= 1):
    # Spec precondition
    return false

  var ctx{.noinit.}: ContextCoreAggregateVerify[DST]

  ctx.init()
  for i in 0 ..< publicKey_msg_pairs.len:
    if not ctx.update(publicKey_msg_pairs[i].publicKey, publicKey_msg_pairs[i].message):
      return false
  return ctx.finish(signature)

func fastAggregateVerify*[T: byte|char](
        publicKeys: openArray[PublicKey],
        proofs: openArray[ProofOfPossession],
        message: openArray[T],
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
    # Spec precondition
    return false
  if not publicKeys[0].popVerify(proofs[0]):
    return false
  var aggPK {.noinit.}: AggregatePublicKey
  aggPK.init(publicKeys[0])
  for i in 1 ..< publicKeys.len:
    if not publicKeys[i].popVerify(proofs[i]):
      return false
    # We assume that the PublicKey is in on curve, in the proper subgroup
    aggPK.aggregate(publicKeys[i])

  var aggAffine{.noinit.}: PublicKey
  aggAffine.finish(aggPK)
  return coreVerifyNoGroupCheck(aggAffine, message, signature, DST)

func fastAggregateVerify*[T: byte|char](
        publicKeys: openArray[PublicKey],
        message: openArray[T],
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
    # Spec precondition
    return false

  var aggAffine{.noinit.}: PublicKey
  if not aggAffine.aggregateAll(publicKeys):
    return false
  return coreVerifyNoGroupCheck(aggAffine, message, signature, DST)
