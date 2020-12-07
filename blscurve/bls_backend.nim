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

const AutoSelectBLST = BLS_FORCE_BACKEND == "auto" and (
  defined(arm64) or defined(arm) or
  defined(amd64) or defined(i386)
)
# Theoretically the BLST library has a fallback for any platform
# but it is missing https://github.com/supranational/blst/issues/46

when (BLS_FORCE_BACKEND == "blst" or AutoSelectBLST) and (
  gorgeEx(getEnv("CC", "gcc") & " -march=native -dM -E -x c /dev/null | grep -q SSSE3").exitCode == 0
  ):
  # BLST supports: x86 and ARM 32 and 64 bits
  # and has optimized SHA256 routines for x86_64 CPU with SSE3
  # It also assumes that all ARM CPUs are Neon instructions capable for SHA256
  const BLS_BACKEND* = BLST
elif BLS_FORCE_BACKEND == "blst" or AutoSelectBLST:
  # CPU doesn't support SSE3 which is used in optimized SHA256
  # On ARM, BLST_PORTABLE will prevent use builtin SHA256
  # which is unsupported by Raspberry Pi, detection via (__ARM_FEATURE_CRYPTO)
  const BLS_BACKEND* = BLST
  {.passC: "-D__BLST_PORTABLE__".}
else:
  # Pure C fallback for all platforms
  const BLS_BACKEND* = Miracl

when BLS_BACKEND == BLST:
  import ./blst/blst_min_pubkey_sig_core
  export blst_min_pubkey_sig_core
else:
  import ./miracl/miracl_min_pubkey_sig_core
  export miracl_min_pubkey_sig_core
