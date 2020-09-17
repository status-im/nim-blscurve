# Nim-BLST
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import std/os

when defined(gcc):
  # * Using ftree-loop-vectorize will miscompile scalar multiplication
  #   for example used to derive the public key in blst_sk_to_pk_in_g1
  # * Using ftree-slp-vectorize miscompiles something when used
  #   in nim-beacon-chain in Travis CI (TODO: test case)
  # no-tree-vectorize removes both
  {.passC: "-fno-tree-vectorize".}
  #
  # From https://github.com/supranational/blst/issues/22
  # it seems like some "restrict" in the library still misscompile
  # We can alternatively remove restrict (for the whole n)
  # {.passC: "-Drestrict=".}

{.compile: ".."/".."/"vendor"/"blst"/"build"/"assembly.S".}
{.compile: ".."/".."/"vendor"/"blst"/"src"/"server.c".}

include ./blst_abi
