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
    var bytes{.noinit.}: array[size, byte]
    bytes.blst_bendian_from_scalar(obj.scalar)
  elif obj is PublicKey:
    const size = 48
    var bytes{.noinit.}: array[size, byte]
    bytes.blst_p1_affine_compress(obj.point)
  elif obj is (Signature or ProofOfPossession):
    const size = 96
    var bytes{.noinit.}: array[size, byte]
    bytes.blst_p2_affine_compress(obj.point)
  elif obj is AggregateSignature:
    const size = 96
    var bytes{.noinit.}: array[size, byte]
    bytes.blst_p2_compress(obj.point)

  bytes.toHex()

func fromBytes*(
       obj: var (Signature|ProofOfPossession),
       raw: array[96, byte] or array[192, byte]
      ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its raw bytes representation.
  ## Returns true on success and false otherwise
  result =
    when raw.len == 96:
      obj.point.blst_p2_uncompress(raw) == BLST_SUCCESS
    elif raw.len == 192:
      obj.point.blst_p2_deserialize(raw) == BLST_SUCCESS
    else: false

  # Infinity signatures are allowed if we receive an empty aggregated signature
  if result:
    result = bool obj.point.blst_p2_affine_in_g2()

func fromBytesKnownOnCurve*(
       obj: var (Signature|ProofOfPossession),
       raw: array[96, byte] or array[192, byte]
      ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its raw bytes representation.
  ## Returns true on success and false otherwise
  ##
  ## The point is known to be on curve and is not group checked
  result =
    when raw.len == 96:
      obj.point.blst_p2_uncompress(raw) == BLST_SUCCESS
    elif raw.len == 192:
      obj.point.blst_p2_deserialize(raw) == BLST_SUCCESS
    else: false
  # Infinity signatures are allowed if we receive an empty aggregated signature

  # Skipped - Known on curve
  # if result:
  #   result = bool obj.point.blst_p2_affine_in_g2()

func fromBytes*(
       obj: var PublicKey,
       raw: array[48, byte] or array[96, byte]
      ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its raw bytes representation.
  ## Returns true on success and false otherwise
  result =
    when raw.len == 48:
      obj.point.blst_p1_uncompress(raw) == BLST_SUCCESS
    elif raw.len == 96:
      obj.point.blst_p1_deserialize(raw) == BLST_SUCCESS
    else: false

  # Infinity public keys are not allowed
  if result:
    result = not bool obj.point.blst_p1_affine_is_inf()
    if result:
      result = bool obj.point.blst_p1_affine_in_g1()

func fromBytesKnownOnCurve*(
       obj: var PublicKey,
       raw: array[48, byte] or array[96, byte]
      ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its raw bytes representation.
  ## Returns true on success and false otherwise
  result =
    when raw.len == 48:
      obj.point.blst_p1_uncompress(raw) == BLST_SUCCESS
    elif raw.len == 96:
      obj.point.blst_p1_deserialize(raw) == BLST_SUCCESS
    else: false

  # Infinity public keys are not allowed
  if result:
    result = not bool obj.point.blst_p1_affine_is_inf()

  # Skipped - Known on curve
  # if result:
  #   result = bool obj.point.blst_p1_affine_in_g1()

func fromBytes*(
       obj: var PublicKey,
       raw: openArray[byte]
      ): bool {.inline.} =
  if raw.len == 48:
    let pa = cast[ptr array[48, byte]](raw[0].unsafeAddr)
    fromBytes(obj, pa[])
  elif raw.len == 96:
    let pa = cast[ptr array[96, byte]](raw[0].unsafeAddr)
    fromBytes(obj, pa[])
  else:
    false

func fromBytes*(
       obj: var (Signature|ProofOfPossession),
       raw: openArray[byte]
      ): bool {.inline.} =
  if raw.len == 96:
    let pa = cast[ptr array[96, byte]](raw[0].unsafeAddr)
    fromBytes(obj, pa[])
  elif raw.len == 192:
    let pa = cast[ptr array[192, byte]](raw[0].unsafeAddr)
    fromBytes(obj, pa[])
  else:
    false

func fromBytes*(
       obj: var SecretKey,
       raw: openArray[byte] or array[32, byte]
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
  try:
    when obj is SecretKey:
      let bytes = hexToPaddedByteArray[32](hexStr)
      obj.fromBytes(bytes)
    elif obj is (Signature or ProofOfPossession):
      let bytes = hexToPaddedByteArray[96](hexStr)
      obj.fromBytes(bytes)
    elif obj is PublicKey:
      if hexStr.len() == 96 * 2:
        let bytes = hexToPaddedByteArray[96](hexStr)
        obj.fromBytes(bytes)
      else:
        let bytes = hexToPaddedByteArray[48](hexStr)
        obj.fromBytes(bytes)
  except ValueError:
    false

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
  ## Returns `true` if the export is successful, `false` otherwise
  ## Note: this overload will serialize to the compressed format most commonly
  ## used.
  blst_p1_affine_compress(dst, obj.point)
  return true

func serialize*(
       dst: var array[96, byte],
       obj: PublicKey): bool {.inline.} =
  ## Serialize the input `obj` in raw binary form and write it
  ## in `dst`.
  ## Returns `true` if the export is successful, `false` otherwise
  ## Note: this overload willl serialize to an uncompressed format that is
  ## faster to deserialize but takes up more space.
  blst_p1_affine_serialize(dst, obj.point)
  return true

func serialize*(
       dst: var array[96, byte],
       obj: Signature|ProofOfPossession): bool {.inline.} =
  ## Serialize the input `obj` in raw binary form and write it
  ## in `dst`.
  ## Returns `true` if the export is successful, `false` otherwise
  ## Note: this overload will serialize to the compressed format most commonly
  ## used.
  blst_p2_affine_compress(dst, obj.point)
  return true

func serialize*(
       dst: var array[192, byte],
       obj: Signature|ProofOfPossession): bool {.inline.} =
  ## Serialize the input `obj` in raw binary form and write it
  ## in `dst`.
  ## Returns `true` if the export is successful, `false` otherwise
  ## Note: this overload willl serialize to an uncompressed format that is
  ## faster to deserialize but takes up more space.
  blst_p2_affine_serialize(dst, obj.point)
  return true

func exportRaw*(secretKey: SecretKey): array[32, byte] {.inline, noinit.}=
  ## Serialize a secret key into its raw binary representation
  discard result.serialize(secretKey)

func exportRaw*(publicKey: PublicKey): array[48, byte] {.inline, noinit.} =
  ## Serialize a public key into its raw compressed binary representation
  discard result.serialize(publicKey)

func exportUncompressed*(publicKey: PublicKey): array[96, byte] {.inline, noinit.} =
  ## Serialize a public key into its raw uncompressed binary representation
  discard result.serialize(publicKey)

func exportRaw*(signature: Signature): array[96, byte] {.inline, noinit.} =
  ## Serialize a signature into its raw compressed binary representation
  discard result.serialize(signature)

func exportUncompressed*(signature: Signature): array[192, byte] {.inline, noinit.} =
  ## Serialize a signature into its raw compressed binary representation
  discard result.serialize(signature)
