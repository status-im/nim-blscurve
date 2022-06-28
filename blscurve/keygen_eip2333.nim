# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import ./eth2_keygen/eth2_keygen
export eth2_keygen

import ./bls_backend
when BLS_BACKEND == BLST:
  import ./eth2_keygen/bls_spec_keygen_blst
else:
  import ./eth2_keygen/bls_spec_keygen_miracl

export keyGen # Spec keyGen
