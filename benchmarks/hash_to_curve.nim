# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  std/random,
  ../blscurve,
  ./bench_templates

when BLS_BACKEND == BLST:
  import
    ../blscurve/blst/blst_abi

# ############################################################
#
#             Benchmark of Hash to G2 of BLS12-381
#                  Using Draft #9 of IETF spec
#
# ############################################################
# https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#appendix-H.10

proc benchHashToG2*(iters: int) =
  const dst = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"
  let msg = "Mr F was here"

  when BLS_BACKEND == BLST:
    var P: blst_p2
    var Paff: blst_p2_affine

    bench("Hash to G2 (Draft #9) + affine conversion", iters):
      blst_hash_to_g2(
        toCV(P, cblst_p2),
        msg,
        dst,
        aug = ""
      )
      blst_p2_to_affine(toCV(Paff, cblst_p2_affine), toCC(P, cblst_p2))

when isMainModule:
  benchHashToG2(1000)
