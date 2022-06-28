# Nim-BLST
# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import std/os

{.compile: "../../vendor/blst/build/assembly.S".}
{.compile: "../../vendor/blst/src/server.c".}

include ./blst_abi, ./blst_aux_abi

# Extra
# ------------------------------------------------------------------------------
# Those are defined in vect.h
# but due to limb_t having 2 different typedefs in blst.h and vect.h (uint64_t and unsigned long long)
# we can't importc both header in the same file
# for static procedures defined in the header

# TODO
# ETH2~BLST difference https://github.com/supranational/blst/issues/11
# We manually allow infinity pubkey with infinity signature (non-constant-time)
# Can be accelerated by removing "vec_is_zero" in the C files
func vec_is_zero*[T](
       v: T
     ): bool {.inline.} =
  # Implementation from BLST vect.h

  static: doAssert sizeof(T) mod sizeof(limb_t) == 0

  var acc = default(limb_t)
  let num = sizeof(T) div sizeof(limb_t)
  const LIMB_T_BITS = sizeof(limb_t) * 8

  let ap = cast[ptr UncheckedArray[limb_t]](v.unsafeAddr)

  for i in 0 ..< num:
    acc = acc or ap[i]

  return bool((not(acc) and (acc-1)) shr (LIMB_T_BITS-1))

func vec_zero*[T](
       v: var T
     ) {.inline.} =
  # Implementation from BLST vect.h

  static: doAssert sizeof(T) mod sizeof(limb_t) == 0

  let num = sizeof(T) div sizeof(limb_t)
  let ap = cast[ptr UncheckedArray[limb_t]](v.unsafeAddr)

  for i in 0 ..< num:
    ap[i] = 0
