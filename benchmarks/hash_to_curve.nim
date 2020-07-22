# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  # Internals
  ../blscurve/[common, milagro, hash_to_curve],
  # Bench
  ./bench_templates

# ############################################################
#
#             Benchmark of Hash to G2 of BLS12-381
#           Using Draft #5 of IETF spec (HKDF-based)
#
# ############################################################
# https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#appendix-C.3

proc benchHashToG2*(iters: int) =
  const dst = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"
  let msg = "msg"

  var point: ECP2_BLS12381

  bench("Hash to G2 (Draft #5)", iters):
    point = hashToG2(msg, dst)


when isMainModule:
  echo "⚠️ Warning: using draft v5 of IETF Hash-To-Curve (HKDF-based)."
  echo "            This is an outdated draft.\n\n"
  benchHashToG2(1000)
