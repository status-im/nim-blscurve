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
when BLS_BACKEND == "miracl":
  import ./eth2_keygen/hkdf_mod_r_miracl
else:
  import ./eth2_keygen/hkdf_mod_r_blst

export keyGen # Spec keyGen
