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

const UseBLST = BLS_FORCE_BACKEND == "auto" or BLS_FORCE_BACKEND == "blst"
const OnX86 = defined(i386) or defined(amd64)
const OnARM = defined(arm) or defined(arm64)

when UseBLST:
  when OnX86:
    # BLST defaults to SSE3 for SHA256 (Pentium 4, 2004)
    # And autodetects MULX and ADCX/ADOX for bigints (Intel Broadwell 2015, AMD Ryzen 2017)
    # It is set either via -march=native on a proper CPU
    # or -madx
    const useSSE3 = gorgeEx(getEnv("CC", "gcc") & " -march=native -dM -E -x c /dev/null | grep -q SSSE3").exitCode == 0
    when not useSSE3:
      {.passC: "-D__BLST_PORTABLE__".}
  elif OnARM:
    # On ARM, BLST can use hardware SHA256.
    # This is the case for all ARM 64-bit device except Raspberry Pis.
    # BLST detects at compile-time the support via
    # the __ARM_FEATURE_CRYPTO compile-time define
    #
    # It is set either with -march=native on a proper CPU
    # or -march=armv8-a+crypto
    # and can be disabled with -D__BLST_PORTABLE__

    # {.passC: "-D__BLST_PORTABLE__".}
    discard
  else:
    {.passC: "-D__BLST_NO_ASM__".}
  const BLS_BACKEND* = BLST
else:
  # Miracl
  const BLS_BACKEND* = Miracl

when BLS_BACKEND == BLST:
  import ./blst/blst_min_pubkey_sig_core
  export blst_min_pubkey_sig_core
else:
  import ./miracl/miracl_min_pubkey_sig_core
  export miracl_min_pubkey_sig_core
