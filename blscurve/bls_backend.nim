# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

const BLS_FORCE_BACKEND*{.strdefine.} = "auto"

static: doAssert BLS_FORCE_BACKEND == "auto" or
                 BLS_FORCE_BACKEND == "blst",
                 """Only "auto" and "blst" backends are valid."""

type BlsBackendKind* = enum
  BLST

const UseBLST = BLS_FORCE_BACKEND == "auto" or BLS_FORCE_BACKEND == "blst"

when UseBLST:
  when defined(amd64) or defined(arm64):
    # BLST has assembly routines and detects the most profitable one at runtime
    # when `__BLST_PORTABLE__` is set
    {.passc: "-D__BLST_PORTABLE__".}
  else:
    # WASM and others - no specialised assembly code available
    {.passc: "-D__BLST_NO_ASM__".}
  const BLS_BACKEND* = BLST

when BLS_BACKEND == BLST:
  import ./blst/[blst_min_pubkey_sig_core, blst_recovery]
  export blst_min_pubkey_sig_core, blst_recovery
