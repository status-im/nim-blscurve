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
  ../blscurve/common,
  ../blscurve/milagro,
  # Bench
  ./bench_templates

# ############################################################
#
#             Benchmark of BLS curve
#              (Barreto-Lynn-Scott)
#
# ############################################################


proc benchScalarMultG1(iters: int) =
  var x = generator1()
  var scal: BIG_384
  random(scal)

  bench("Scalar multiplication G1", iters):
    x.mul(scal)

proc benchScalarMultG2(iters: int) =
  var x = generator2()
  var scal: BIG_384
  random(scal)

  bench("Scalar multiplication G2", iters):
    x.mul(scal)

benchScalarMultG1(1000)
benchScalarMultG2(1000)
