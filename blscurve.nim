# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

const BLS_USE_IETF_API {.booldefine.} = false

when BLS_USE_IETF_API:
  {.error: "IETF API is not implemented".}
else:
  import blscurve/bls_old_spec
  export bls_old_spec
