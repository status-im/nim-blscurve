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

func fromHex*[T: SecretKey|PublicKey|Signature|ProofOfPossession](
       obj: var T,
       hexStr: string
     ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its hex raw bytes representation.
  ## Returns true on a success and false otherwise
  when obj is SecretKey:
    result = obj.intVal.fromHex(hexStr)
  else:
    result = obj.point.fromHex(hexStr)

func fromBytes*[T: SecretKey|PublicKey|Signature|ProofOfPossession](
       obj: var T,
       raw: openarray[byte]
      ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its raw bytes representation.
  ## Returns true on success and false otherwise
  when obj is SecretKey:
    result = obj.intVal.fromBytes(raw)
  else:
    result = obj.point.fromBytes(raw)

func toHex*(obj: SecretKey|PublicKey|Signature|ProofOfPossession): string {.inline.} =
  ## Return the hex representation of a BLS signature scheme object
  ## Signature and Proof-of-posessions are serialized in compressed form
  when obj is SecretKey:
    result = obj.intVal.toHex()
  else:
    result = obj.point.toHex()

func serialize*(
       dst: var openarray[byte],
       obj: SecretKey|PublicKey|Signature|ProofOfPossession): bool {.inline.} =
  ## Serialize the input `obj` in raw binary form and write it
  ## in `dst`.
  ## Returns `true` if the export is successful, `false` otherwise
  when obj is SecretKey:
    result = obj.intVal.toBytes(dst)
  else:
    result = obj.point.toBytes(dst)

const
  RawSecretKeySize = MODBYTES_384
  RawPublicKeySize = MODBYTES_384
  RawSignatureSize = MODBYTES_384 * 2

func exportRaw*(secretKey: SecretKey): array[RawSecretKeySize, byte] {.inline.}=
  ## Serialize a secret key into its raw binary representation
  # TODO: the SecretKey size is actually not 384 bit
  #       but 255 bit since the curve order requires 255-bit
  #       What uses exportRaw?
  discard result.serialize(secretKey)

func exportRaw*(publicKey: PublicKey): array[RawPublicKeySize, byte] {.inline.}=
  ## Serialize a public key into its raw binary representation
  discard result.serialize(publicKey)

func exportRaw*(signature: Signature): array[RawSignatureSize, byte] {.inline.}=
  ## Serialize a signature into its raw binary representation
  discard result.serialize(signature)
