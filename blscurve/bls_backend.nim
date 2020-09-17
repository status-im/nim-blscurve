# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import os

const BLS_FORCE_BACKEND*{.strdefine.} = "auto"

static: doAssert BLS_FORCE_BACKEND == "auto" or
                 BLS_FORCE_BACKEND == "miracl" or
                 BLS_FORCE_BACKEND == "blst",
                 """Only "auto", "blst" and "miracl" backends are valid."""

type BlsBackendKind* = enum
  BLST
  Miracl

when BLS_FORCE_BACKEND == "blst" or (
  BLS_FORCE_BACKEND == "auto" and
    sizeof(int) == 8 and
    (defined(arm64) or (
      defined(amd64) and
      gorgeEx(getEnv("CC", "gcc") & " -march=native -dM -E -x c /dev/null | grep -q SSSE3").exitCode == 0))
  ):
  # BLST supports: x86_64 and ARM64
  # and has optimized SHA256 routines for x86_64 CPU with SSE3
  const BLS_BACKEND* = BLST
elif BLS_FORCE_BACKEND == "auto" and defined(amd64):
  # CPU doesn't support SSE3 which is used in optimized SHA256
  const BLS_BACKEND* = BLST
  {.passC: "-D__BLST_PORTABLE__".}
else:
  # Pure C fallback for all platforms
  const BLS_BACKEND* = Miracl

when BLS_BACKEND == BLST:
  import ./blst/bls_sig_min_pubkey_size_pop
  export bls_sig_min_pubkey_size_pop
else:
  import
    ./miracl/bls_signature_scheme
  export
    SecretKey, PublicKey, Signature, ProofOfPossession,
    AggregateSignature,
    `==`,
    init, aggregate, finish,
    sign, verify, aggregateVerify, fastAggregateVerify,
    privToPub,
    fromHex, fromBytes, toHex, serialize, exportRaw
