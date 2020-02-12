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

import
  ./bls_signature_scheme, ./common

func fromHex*(
       obj: var SecretKey|PublicKey|Signature|ProofOfPossession,
       hexStr: string
     ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its hex raw bytes representation.
  ## Returns true on asuccess and false otherwise
  when obj is SecretKey:
    result = obj.intVal.fromHex(hexStr)
  else:
    result = obj.point.fromHex(hexStr)

func fromBytes*(
       obj: var SecretKey|PublicKey|Signature|ProofOfPossession,
       raw: openarray[byte]
      ): bool {.inline.} =
  ## Initialize a BLS signature scheme object from
  ## its raw bytes representation.
  ## Returns true on success and false otherwise
  when obj is SecretKey:
    result = obj.intVal.fromBytes(hexStr)
  else:
    result = obj.point.fromBytes(hexStr)
