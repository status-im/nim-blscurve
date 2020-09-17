# Nim-BLST
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import std/os

{.compile: ".."/".."/"vendor"/"blst"/"build"/"assembly.S".}
{.compile: ".."/".."/"vendor"/"blst"/"src"/"server.c".}

include ./blst_abi
