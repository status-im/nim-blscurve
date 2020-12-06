# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Implementation of IO routines to serialize to and from
# the types defined in
# - https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-00#section-5.5
# - https://github.com/cfrg/draft-irtf-cfrg-bls-signature

# This file should be included to have access to private fields
# It is kept separated as it does not fall under the IETF BLS specification

func toHex*(
       obj: SecretKey|PublicKey|Signature|ProofOfPossession|AggregateSignature,
     ): string =
  ## Return the hex representation of a BLS signature scheme object
  ## They are serialized in compressed form
  when obj is SecretKey:
    const size = 32
    var bytes{.noInit.}: array[size, byte]
    bytes.blst_bendian_from_scalar(obj.scalar)
  elif obj is PublicKey:
    const size = 48
    var bytes{.noInit.}: array[size, byte]
    bytes.blst_p1_affine_compress(obj.point)
  elif obj is (Signature or ProofOfPossession):
    const size = 96
    var bytes{.noInit.}: array[size, byte]
    bytes.blst_p2_affine_compress(obj.point)
  elif obj is AggregateSignature:
    const size = 96
    var bytes{.noInit.}: array[size, byte]
    bytes.blst_p2_compress(obj.point)

  result = bytes.toHex()

func fromBytes*(
       obj: var (Signature|ProofOfPossession),
       raw: openarray[byte] or array[96, byte]
      ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its raw bytes representation.
  ## Returns true on success and false otherwise
  const L = 96
  when raw is array:
    result = obj.point.blst_p2_uncompress(raw) == BLST_SUCCESS
  else:
    if raw.len != L:
      return false
    let pa = cast[ptr array[L, byte]](raw[0].unsafeAddr)
    result = obj.point.blst_p2_uncompress(pa[]) == BLST_SUCCESS
  # Infinity signatures are allowed if we receive an empty aggregated signature
  if result:
    result = bool obj.point.blst_p2_affine_in_g2()

func fromBytes*(
       obj: var PublicKey,
       raw: openarray[byte] or array[48, byte]
      ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its raw bytes representation.
  ## Returns true on success and false otherwise
  const L = 48
  when raw is array:
    result = obj.point.blst_p1_uncompress(raw) == BLST_SUCCESS
  else:
    if raw.len != L:
      return false
    let pa = cast[ptr array[L, byte]](raw[0].unsafeAddr)
    result = obj.point.blst_p1_uncompress(pa[]) == BLST_SUCCESS
  # Infinity public keys are not allowed
  if result:
    result = not bool obj.point.blst_p1_affine_is_inf()
  if result:
    result = bool obj.point.blst_p1_affine_in_g1()

func fromBytes*(
       obj: var SecretKey,
       raw: openarray[byte] or array[32, byte]
      ): bool {.inline.} =
  ## Initialize a BLS secret key from
  ## its raw bytes representation.
  ## Returns true on success and false otherwise
  const L = 32
  when raw is array:
    obj.scalar.blst_scalar_from_bendian(raw)
  else:
    if raw.len != 32:
      return false
    let pa = cast[ptr array[L, byte]](raw[0].unsafeAddr)
    obj.scalar.blst_scalar_from_bendian(pa[])
  if obj.vec_is_zero():
    return false
  if not obj.scalar.blst_sk_check().bool:
    return false
  return true

func fromHex*(
       obj: var (SecretKey|PublicKey|Signature|ProofOfPossession),
       hexStr: string
     ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its hex raw bytes representation.
  ## Returns true on a success and false otherwise
  when obj is SecretKey:
    const size = 32
  elif obj is PublicKey:
    const size = 48
  elif obj is (Signature or ProofOfPossession):
    const size = 96

  try:
    let bytes = hexToPaddedByteArray[size](hexStr)
    return obj.fromBytes(bytes)
  except:
    return false

func serialize*(
       dst: var array[32, byte],
       obj: SecretKey): bool {.inline.} =
  ## Serialize the input `obj` in raw binary form and write it
  ## in `dst`.
  ## Returns `true` if the export is succesful, `false` otherwise
  blst_bendian_from_scalar(dst, obj.scalar)
  return true

func serialize*(
       dst: var array[48, byte],
       obj: PublicKey): bool {.inline.} =
  ## Serialize the input `obj` in raw binary form and write it
  ## in `dst`.
  ## Returns `true` if the export is succesful, `false` otherwise
  blst_p1_affine_compress(dst, obj.point)
  return true

func serialize*(
       dst: var array[96, byte],
       obj: Signature|ProofOfPossession): bool {.inline.} =
  ## Serialize the input `obj` in raw binary form and write it
  ## in `dst`.
  ## Returns `true` if the export is succesful, `false` otherwise
  blst_p2_affine_compress(dst, obj.point)
  return true

func exportRaw*(secretKey: SecretKey): array[32, byte] {.inline.}=
  ## Serialize a secret key into its raw binary representation
  discard result.serialize(secretKey)

func exportRaw*(publicKey: PublicKey): array[48, byte] {.inline.}=
  ## Serialize a public key into its raw binary representation
  discard result.serialize(publicKey)

func exportRaw*(signature: Signature): array[96, byte] {.inline.}=
  ## Serialize a signature into its raw binary representation
  discard result.serialize(signature)
