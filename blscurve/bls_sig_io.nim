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
  ## Returns true on asuccess and false otherwise
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
    result = obj.intVal.fromBytes(hexStr)
  else:
    result = obj.point.fromBytes(hexStr)

func toHex*(obj: SecretKey|PublicKey|Signature|ProofOfPossession): string =
  ## Return the hex representation of a BLS signature scheme object
  ## Signature and Proof-of-posessions are serialized in compressed form
  when obj is SecretKey:
    result = obj.intVal.toHex()
  else:
    result = obj.point.toHex()
